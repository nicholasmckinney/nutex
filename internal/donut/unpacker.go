package donut

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/Binject/go-donut/donut"
	"golang.org/x/exp/slices"
	"io"
	"nutextractor/internal/common"
	"os"
	"strconv"
	"strings"
	"unsafe"
)

type AMSIBypassPolicy uint32
type CompressionEngine uint32
type EntropyLevel uint32
type ExitAction uint32
type InstanceType uint32
type ModuleType uint32

var arch32Sig = []byte{0x59, 0x5a, 0x51, 0x52}
var multiSig = []byte{0x59, 0x31, 0xc0, 0x48}

const (
	ModuleTypeDotnetDLL ModuleType = 1
	ModuleTypeDotnetExe ModuleType = 2
	ModuleTypeNativeDLL ModuleType = 3
	ModuleTypeNativeExe ModuleType = 4
	ModuleTypeVBScript  ModuleType = 5
	ModuleTypeJScript   ModuleType = 6

	NoCompression CompressionEngine = 1
	APLib         CompressionEngine = 2
	LZNT1         CompressionEngine = 3
	Xpress        CompressionEngine = 4
	XpressHuffman CompressionEngine = 5

	NoEntropy      EntropyLevel = 1
	RandomEntropy  EntropyLevel = 2
	DefaultEntropy EntropyLevel = 3

	ExitThread  ExitAction = 1
	ExitProcess ExitAction = 2

	EmbeddedModule   InstanceType = 1
	RemoteHTTPModule InstanceType = 2
	RemoteDNSModule  InstanceType = 3

	NoBypassPolicy       AMSIBypassPolicy = 1
	AbortOnFail          AMSIBypassPolicy = 2
	ContinueOnBypassFail AMSIBypassPolicy = 3
)

func (mt ModuleType) String() string {
	switch mt {
	case ModuleTypeDotnetDLL:
		return ".NET DLL"
	case ModuleTypeDotnetExe:
		return ".NET EXE"
	case ModuleTypeNativeDLL:
		return "Native DLL"
	case ModuleTypeNativeExe:
		return "Native EXE"
	case ModuleTypeVBScript:
		return "VBScript"
	case ModuleTypeJScript:
		return "JScript"
	default:
		return "UNKNOWN"
	}
}

func (algo CompressionEngine) String() string {
	switch algo {
	case NoCompression:
		return "No Compression"
	case APLib:
		return "aPLib"
	case LZNT1:
		return "LZNT1"
	case Xpress:
		return "Xpress"
	case XpressHuffman:
		return "XpressHuffman"
	default:
		return "UNKNOWN"
	}
}

func (level EntropyLevel) String() string {
	switch level {
	case NoEntropy:
		return "No Entropy"
	case RandomEntropy:
		return "Random Names"
	case DefaultEntropy:
		return "Random Names + Symmetric Encryption"
	default:
		return "UNKNOWN"
	}
}

func (action ExitAction) String() string {
	switch action {
	case ExitThread:
		return "Exits Thread"
	case ExitProcess:
		return "Exits Process"
	default:
		return "UNKNOWN"
	}
}

func (instance InstanceType) String() string {
	switch instance {
	case EmbeddedModule:
		return "Embedded"
	case RemoteHTTPModule:
		return "Remote HTTP"
	case RemoteDNSModule:
		return "Remote DNS"
	default:
		return "UNKNOWN"
	}
}

func (policy AMSIBypassPolicy) String() string {
	switch policy {
	case NoBypassPolicy:
		return "No Bypass"
	case AbortOnFail:
		return "Abort On Fail"
	case ContinueOnBypassFail:
		return "Continue on Bypass Failure"
	default:
		return "UNKNOWN"
	}
}

type Factory struct {
}

func (f *Factory) Build(content []byte) common.Unpacker {
	return New(content)
}

type Unpacker struct {
	buf *bytes.Reader
}

type Payload struct {
	Metadata Metadata
	Content  []byte
}

// https://github.com/TheWover/donut/blob/dafea1702ce2e71d5139c4d583627f7ee740f3ae/include/encrypt.h#L47-L48
// https://github.com/TheWover/donut/blob/dafea1702ce2e71d5139c4d583627f7ee740f3ae/include/donut.h#L105-L106
const KeyLength = 16
const BlockLength = 16
const MaxNameLength = 256
const SignatureLength = 8

// https://github.com/TheWover/donut/blob/dafea1702ce2e71d5139c4d583627f7ee740f3ae/include/donut.h#L233-L236
type crypt struct {
	MasterKey [KeyLength]uint8
	Counter   [BlockLength]uint8
}

// https://github.com/TheWover/donut/blob/dafea1702ce2e71d5139c4d583627f7ee740f3ae/include/donut.h#L97-L102
type guid struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

// https://github.com/TheWover/donut/blob/dafea1702ce2e71d5139c4d583627f7ee740f3ae/include/donut.h#L239-L258
type module struct {
	ModuleType        ModuleType
	RunsEntryAsThread uint32
	CompressionEngine CompressionEngine

	// https://github.com/TheWover/donut/blob/dafea1702ce2e71d5139c4d583627f7ee740f3ae/include/donut.h#L181
	RuntimeVersion            [MaxNameLength]byte
	Domain                    [MaxNameLength]byte
	DotnetClassName           [MaxNameLength]byte
	InvokedMethod             [MaxNameLength]byte
	MethodParameters          [MaxNameLength]byte
	IsUnicode                 uint32
	Signature                 [SignatureLength]byte
	MessageAuthenticationCode uint64
	CompressedSize            uint32
	UncompressedSize          uint32
	// payload data follows immediately after UncompressedSize, but is variably-sized so can't be built into struct
}

// https://github.com/TheWover/donut/blob/dafea1702ce2e71d5139c4d583627f7ee740f3ae/include/donut.h#L261-L405
type instanceHeader struct {
	InstanceSize           uint32
	InstanceDecryptionKey  crypt
	MaruInitialValue       uint64
	ApiHashes              [516]uint8
	TerminateProcessOnExit uint32
	EntropyLevel           EntropyLevel
	OriginalEntryPoint     uint64
}

// body is encrypted by instanceHeader.crypt, and so they can't be unified as we will have to decrypt below first
type instanceBody struct {
	ApiHashCount               uint32
	LoadDLLs                   [MaxNameLength]byte
	Dataname                   [8]byte
	Kernelbase                 [12]byte
	Amsi                       [8]byte
	Clr                        [4]byte
	Wldp                       [8]byte
	CmdSymbols                 [MaxNameLength]byte
	ExitAPI                    [MaxNameLength]byte
	BypassPolicy               AMSIBypassPolicy
	WldpQuery                  [32]byte
	WldpIsApproved             [32]byte
	AsmiInit                   [16]byte
	AmsiScanBuf                [16]byte
	AmsiScanStr                [16]byte
	Wscript                    [8]byte
	WscriptExe                 [12]byte
	IidIUnknown                guid
	IidIDispatch               guid
	ClsidCLRMetaHost           guid
	IidICLRMetaHost            guid
	IidICLRRuntimeInfo         guid
	ClsidCorRuntimeHost        guid
	IidICorRuntimeHost         guid
	IidAppDomain               guid
	ClsidScriptLanguage        guid
	IidIHost                   guid
	IidIActiveScript           guid
	IidIActiveScriptSite       guid
	IidIActiveScriptSiteWindow guid
	IidIActiveScriptParse32    guid
	IidIActiveScriptParse64    guid
	InstanceType               InstanceType
	RemoteServer               [MaxNameLength]byte
	HttpReq                    [8]byte
	Signature                  [MaxNameLength]uint8
	MessageAuthenticationCode  uint64
	ModuleDecryptionKey        crypt
	ModuleSize                 uint64
	DonutModule                module
}

type Instance struct {
	header  *instanceHeader
	body    *instanceBody
	payload []byte
}

type Metadata struct {
	Arch common.CPUArch
}

func New(content []byte) *Unpacker {
	return &Unpacker{buf: bytes.NewReader(content)}
}

func (i *Instance) String() string {
	var sb strings.Builder
	fmt.Fprintln(&sb, "Donut Instance")
	if i.header != nil {
		fmt.Fprintf(&sb, "[ Entropy Level : %s\n", i.header.EntropyLevel)
	} else {
		fmt.Fprintln(&sb, "[!] No instance header present!")
	}

	if i.body != nil {
		fmt.Fprintf(&sb, "[ Instance Type: %s\n", i.body.InstanceType)
		if i.body.InstanceType == RemoteHTTPModule {
			fmt.Fprintf(&sb, "[ HTTP Server: %s\n", i.body.RemoteServer)
			fmt.Fprintf(&sb, "[ HTTP Verb: %s\n", i.body.HttpReq)
		} else {
			fmt.Fprintf(&sb, "[ Module Type: %s\n", i.body.DonutModule.ModuleType)
			fmt.Fprintf(&sb, "[ Runs EP as Thread: %s\n", strconv.FormatBool(i.body.DonutModule.RunsEntryAsThread > 0))

			dotnetTypes := []ModuleType{ModuleTypeDotnetDLL, ModuleTypeDotnetExe}
			if slices.Contains(dotnetTypes, i.body.DonutModule.ModuleType) {
				fmt.Fprintf(&sb, "[ CLR Runtime Version: %s\n", i.body.DonutModule.RuntimeVersion)
				fmt.Fprintf(&sb, "[ .NET Class: %s\n", i.body.DonutModule.DotnetClassName)
				fmt.Fprintf(&sb, "[ .NET Domain: %s\n", i.body.DonutModule.Domain)
			}

			if string(i.body.DonutModule.InvokedMethod[:]) != "" {
				fmt.Fprintf(&sb, "[ Invoked Method: %s\n", i.body.DonutModule.InvokedMethod)
			}

			// https://github.com/TheWover/donut/blob/dafea1702ce2e71d5139c4d583627f7ee740f3ae/donut.c#L777-L781
			// with entropy for a target native EXE, donut will generate random 4 byte ASCII string + 1 byte space before actual args
			if string(i.body.DonutModule.MethodParameters[:]) != "" {
				var params []byte
				if i.body.DonutModule.ModuleType == ModuleTypeNativeExe {
					params = i.body.DonutModule.MethodParameters[5:] // <- read actual args, not prefix garbage
				} else {
					params = i.body.DonutModule.MethodParameters[:]
				}
				paramBuffer := bytes.NewBuffer(params)
				fmt.Fprintf(&sb, "[ EP Parameters: %s\n", paramBuffer.String())
			}

			fmt.Fprintf(&sb, "[ Compression: %s\n", i.body.DonutModule.CompressionEngine)
		}
	} else {
		fmt.Fprintln(&sb, "[!] No instance body present!")
	}

	return sb.String()
}

func (i *Instance) Decrypt(bodyBytes []byte) error {
	if i.header == nil {
		return fmt.Errorf("no instance header present")
	}

	// decrypt instance
	var mkBytes []byte
	var ctrBytes []byte
	var decryptedBytes []byte
	mkBytes = i.header.InstanceDecryptionKey.MasterKey[:]
	ctrBytes = i.header.InstanceDecryptionKey.Counter[:]
	decryptedBytes = donut.Encrypt(mkBytes, ctrBytes, bodyBytes)

	var body instanceBody
	typeOffset := unsafe.Offsetof(body.InstanceType)
	// InstanceType == uint32 == 4 bytes
	instanceType := binary.LittleEndian.Uint32(decryptedBytes[typeOffset : typeOffset+4])
	reader := bytes.NewReader(decryptedBytes)
	err := binary.Read(reader, binary.LittleEndian, &body)
	if err != nil {
		return fmt.Errorf("failed to read decrypted instance body")
	}
	i.body = &body
	// Reference: https://github.com/TheWover/donut/blob/dafea1702ce2e71d5139c4d583627f7ee740f3ae/donut.c#L993-L1032
	// Reference: https://github.com/TheWover/donut/blob/dafea1702ce2e71d5139c4d583627f7ee740f3ae/donut.c#L1113-L1117
	// if default entropy is enabled AND the module is downloaded over HTTP, then the module
	// is not embedded in the file. We can only obtain the HTTP URL and Verb to retrieve it
	// The module in that case is actually saved to the disk rather than embedded in the donut instance
	// (see: https://github.com/TheWover/donut/blob/dafea1702ce2e71d5139c4d583627f7ee740f3ae/donut.c#L1035-L1039)
	if instanceType != uint32(RemoteHTTPModule) {
		payloadSize := len(decryptedBytes) - binary.Size(body)
		payload := make([]byte, payloadSize)
		err = binary.Read(reader, binary.LittleEndian, &payload)
		if err != nil {
			return fmt.Errorf("failed to read decrypted payload")
		}
		i.payload = payload
	}
	return nil
}

func (u *Unpacker) Name() string {
	return "Donut Loader"
}

func (u *Unpacker) Extract() (*Instance, error) {
	var err error
	var meta Metadata
	meta.Arch = common.Unknown

	samples := make(map[common.CPUArch][]byte)
	samples[common.MultiArch] = multiSig
	samples[common.X86] = arch32Sig

	// https://github.com/TheWover/donut/blob/dafea1702ce2e71d5139c4d583627f7ee740f3ae/donut.c#L1235
	// Skip jump inst
	u.buf.Seek(1, io.SeekStart)

	// https://github.com/TheWover/donut/blob/dafea1702ce2e71d5139c4d583627f7ee740f3ae/donut.c#L1236
	// despite saying PUT_WORD, this actually puts 4 byte integer of offset to loader AFTER current offset
	// this means from after offset 5 (1 byte rel jump + 4 byte instance length) + instance length
	var instanceLengthBytes uint32
	err = binary.Read(u.buf, binary.LittleEndian, &instanceLengthBytes)
	if err != nil {
		return nil, fmt.Errorf("unable to read instance length. %v", err)
	}

	donutInstanceBytes := make([]byte, instanceLengthBytes)
	err = binary.Read(u.buf, binary.LittleEndian, &donutInstanceBytes)
	if err != nil {
		return nil, fmt.Errorf("unable to read donut instance. %v", err)
	}

	// https://github.com/TheWover/donut/blob/dafea1702ce2e71d5139c4d583627f7ee740f3ae/donut.c#L1239
	// Read the pop ecx + 3 more bytes to determine arch
	archBytes := make([]byte, 4)
	err = binary.Read(u.buf, binary.LittleEndian, &archBytes)
	for arch, sample := range samples {
		if bytes.Equal(archBytes, sample) {
			meta.Arch = arch
		}
	}
	if meta.Arch == common.Unknown {
		return nil, fmt.Errorf("unable to identify architecture")
	}

	var header instanceHeader
	headerSize := binary.Size(header)
	headerBytes := donutInstanceBytes[:headerSize]
	header, err = u.extractHeader(headerBytes)
	if err != nil {
		return nil, fmt.Errorf("unable to extract donut instance header. %v", err)
	}

	donutInstance := Instance{header: &header}
	if donutInstance.header.EntropyLevel == DefaultEntropy {
		err = donutInstance.Decrypt(donutInstanceBytes[headerSize:])
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt instance body. %v", err)
		}
	} else { // body is plaintext, along with payload
		reader := bytes.NewReader(donutInstanceBytes[headerSize:])
		body := instanceBody{}
		err = binary.Read(reader, binary.LittleEndian, &body)
		if err != nil {
			return nil, fmt.Errorf("failed to read instance body. %v", err)
		}
		donutInstance.body = &body

		// non-embedded payloads can't be extracted from the shellcode. We can only retrieve the metadata (e.g. URL)
		// Donut code shows that author may have had ideas to retrieve from DNS server but that does not appear
		// to be implemented as of 10/26/2022
		if donutInstance.body.InstanceType != RemoteHTTPModule {
			payload, err := io.ReadAll(reader)
			if err != nil {
				return nil, fmt.Errorf("failed to read embedded payload. %v", err)
			}
			donutInstance.payload = payload
		}
	}

	if donutInstance.body.InstanceType != RemoteHTTPModule && donutInstance.body.DonutModule.CompressionEngine != NoCompression {
		decompressed, err := DecompressBuffer(
			donutInstance.body.DonutModule.CompressionEngine,
			donutInstance.body.DonutModule.UncompressedSize,
			donutInstance.payload,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to decompress payload of uncompressed size (%d). %v", donutInstance.body.DonutModule.UncompressedSize, err)
		}
		donutInstance.payload = decompressed
	}

	// the rest of the file is just the loader code which is not unique to the packed file
	// so we can ignore it

	//result += donutInstance.String()
	//result += fmt.Sprintf("[ CPU Arch: %s\n", common.ArchToString(meta.Arch))
	return &donutInstance, nil
}

func (u *Unpacker) Identified() (string, error) {
	instance, err := u.Extract()
	if err != nil {
		return "", fmt.Errorf("failed to identify attributes of donut instance. %v", err)
	}

	return instance.String(), nil
}

func (u *Unpacker) extractHeader(headerBytes []byte) (instanceHeader, error) {
	var result instanceHeader
	reader := bytes.NewReader(headerBytes)
	err := binary.Read(reader, binary.LittleEndian, &result)
	if err != nil {
		return result, fmt.Errorf("failed to read instance bytes")
	}
	return result, nil
}

func (u *Unpacker) CanUnpack() bool {
	_, err := u.Extract()
	if err != nil {
		return false
	}
	return true
}

func (u *Unpacker) UnpackToFile(path string) error {
	instance, err := u.Extract()
	if err != nil {
		return fmt.Errorf("failed to unpack to file. %v", err)
	}
	err = os.WriteFile(path, instance.payload, os.ModePerm)
	if err != nil {
		return fmt.Errorf("failed to write payload to file. %v", err)
	}
	return nil
}
