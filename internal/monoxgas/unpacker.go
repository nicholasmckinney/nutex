package monoxgas

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/saferwall/pe"
	"io"
	"math/bits"
	"nutextractor/internal/common"
	"os"
	"strconv"
)

var relativeJump = [5]byte{0xe8, 0, 0, 0, 0}

// https://github.com/monoxgas/sRDI/blob/9fdd5c44383039519accd1e6bac4acd5a046a92c/Python/ShellcodeRDI.py#L76-L80
var arch64Sig = [4]byte{0x59, 0x49, 0x89, 0xc8}

// https://github.com/monoxgas/sRDI/blob/master/Python/ShellcodeRDI.py#L158-L168
var arch32Sig = [6]byte{0x58, 0x55, 0x89, 0xe5, 0x89, 0xc2}

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
	DLL      []byte
}
type Metadata struct {
	FunctionHash uint32
	UserData     string
	Flags        uint32
	Arch         common.CPUArch
}

func (p *Payload) TargetFunction() (string, error) {
	fmt.Printf("[*] DLL Size (bytes): %d\n", len(p.DLL))
	fmt.Printf("[*] First 5 bytes: %x\n", p.DLL[:5])
	dll, err := pe.NewBytes(p.DLL, &pe.Options{})
	if err != nil {
		return "", fmt.Errorf("unable to open embedded DLL. %v", err)
	}
	err = dll.Parse()
	if err != nil {
		return "", fmt.Errorf("unable to parse embedded DLL. %v", err)
	}

	fmt.Printf("[*] Target Function Hash: 0x%x\n", p.Metadata.FunctionHash)

	fmt.Printf("[*] Number of Exports: %d\n", len(dll.Export.Functions))
	for _, export := range dll.Export.Functions {
		var funcHash uint32
		cstr := bytes.NewBufferString(export.Name).Bytes()
		cstr = append(cstr, 0x00) // add null byte to match c-string
		for _, char := range cstr {
			// https://github.com/monoxgas/sRDI/blob/9fdd5c44383039519accd1e6bac4acd5a046a92c/Python/ShellcodeRDI.py#L51
			// 13 is a constant for rotation
			funcHash = bits.RotateLeft32(funcHash, -13) // rotating left by negative number makes it rotate right
			funcHash += uint32(char)
		}
		if funcHash == p.Metadata.FunctionHash {
			return export.Name, nil
		}
	}

	return "", fmt.Errorf("no matching exported function for hash: 0x%x\n", p.Metadata.FunctionHash)
}

func (m *Metadata) ClearsHeader() bool {
	return m.Flags&0x1 == 1
}

func (m *Metadata) ClearsMemory() bool {
	return m.Flags&0x2 == 0x2
}

func (m *Metadata) PassesShellcodeBaseToTargetFunction() bool {
	return m.Flags&0x8 == 0x8
}

func (m *Metadata) ObfuscatesImports() bool {
	return m.Flags&0x4 == 0x4
}

func New(content []byte) *Unpacker {
	return &Unpacker{buf: bytes.NewReader(content)}
}

func (u *Unpacker) Name() string {
	return "Monoxgas sRDI"
}

func (u *Unpacker) isAMD64() (bool, error) {
	var err error

	u.buf.Seek(int64(len(relativeJump)), io.SeekStart)

	archComparator := [4]byte{}
	err = binary.Read(u.buf, binary.LittleEndian, &archComparator)
	if err != nil {
		return false, fmt.Errorf("unable to determine if architecture of input was AMD64. %v", err)
	}

	if archComparator == arch64Sig {
		return true, nil
	}

	return false, nil
}

func (u *Unpacker) isX86() (bool, error) {
	var err error

	u.buf.Seek(int64(len(relativeJump)), io.SeekStart)

	archComparator := [6]byte{}
	err = binary.Read(u.buf, binary.LittleEndian, &archComparator)
	if err != nil {
		return false, fmt.Errorf("unable to determine if architecture of input was x86. %v", err)
	}

	if archComparator == arch32Sig {
		return true, nil
	}

	return false, nil
}

func (u *Unpacker) unpack64bit() (Payload, error) {
	var err error
	var result Payload
	var meta Metadata

	u.buf.Seek(int64(len(relativeJump))+int64(len(arch64Sig)), io.SeekStart)
	// Skip MOV EDX byte to get unsigned 32-bit operand
	// https://github.com/monoxgas/sRDI/blob/master/Python/ShellcodeRDI.py#L83
	u.buf.Seek(1, io.SeekCurrent)

	err = binary.Read(u.buf, binary.LittleEndian, &meta.FunctionHash)
	if err != nil {
		return result, fmt.Errorf("unable to get function hash. %v", err)
	}

	// https://github.com/monoxgas/sRDI/blob/master/Python/ShellcodeRDI.py#L88
	u.buf.Seek(3, io.SeekCurrent)

	var userDataOffset uint32
	err = binary.Read(u.buf, binary.LittleEndian, &userDataOffset)
	if err != nil {
		return result, fmt.Errorf("unable to get user data offset. %v", err)
	}

	// https://github.com/monoxgas/sRDI/blob/master/Python/ShellcodeRDI.py#L93
	u.buf.Seek(2, io.SeekCurrent)
	var userDataLength uint32
	err = binary.Read(u.buf, binary.LittleEndian, &userDataLength)
	if err != nil {
		return result, fmt.Errorf("unable to get user data length. %v", err)
	}

	// https://github.com/monoxgas/sRDI/blob/master/Python/ShellcodeRDI.py#L96-L114
	u.buf.Seek(20, io.SeekCurrent)

	var dllOffset uint32
	err = binary.Read(u.buf, binary.LittleEndian, &dllOffset)
	if err != nil {
		return result, fmt.Errorf("unable to get dll offset. %v", err)
	}

	// User data location follows DLL, so by subtracting the dll offset from the user data offset we can get the DLL size
	// https://github.com/monoxgas/sRDI/blob/master/Python/ShellcodeRDI.py#L89
	dllLength := userDataOffset - dllOffset

	// https://github.com/monoxgas/sRDI/blob/master/Python/ShellcodeRDI.py#L118-L119
	u.buf.Seek(4, io.SeekCurrent)
	err = binary.Read(u.buf, binary.LittleEndian, &meta.Flags)
	if err != nil {
		return result, fmt.Errorf("unable to get flags data. %v", err)
	}

	// https://github.com/monoxgas/sRDI/blob/master/Python/ShellcodeRDI.py#L123-L134
	// Bootstrap shellcode size is 69 bytes. Adding 5 gets us to the end of the bootstrap.
	// Then we add the DLL offset to read the DLL
	u.buf.Seek(int64(dllOffset)+5, io.SeekStart)
	dllBytes := make([]byte, int(dllLength))
	err = binary.Read(u.buf, binary.LittleEndian, &dllBytes)
	if err != nil {
		return result, fmt.Errorf("unable to extract DLL bytes. %v", err)
	}
	result.DLL = dllBytes

	userDataBytes := make([]byte, int(userDataLength))
	err = binary.Read(u.buf, binary.LittleEndian, &userDataBytes)
	if err != nil {
		return result, fmt.Errorf("unable to extract user data. %v", err)
	}
	meta.UserData = string(userDataBytes)
	result.Metadata = meta
	return result, nil
}

func (u *Unpacker) unpack32bit() (Payload, error) {
	var err error
	var result Payload
	var meta Metadata

	u.buf.Seek(int64(len(relativeJump))+int64(len(arch32Sig)), io.SeekStart)
	// https://github.com/monoxgas/sRDI/blob/master/Python/ShellcodeRDI.py#L158-L171
	u.buf.Seek(1, io.SeekCurrent)

	err = binary.Read(u.buf, binary.LittleEndian, &meta.Flags)
	if err != nil {
		return result, fmt.Errorf("unable to read flag data. %v", err)
	}

	u.buf.Seek(3, io.SeekCurrent)

	var userDataOffset uint32
	err = binary.Read(u.buf, binary.LittleEndian, &userDataOffset)
	if err != nil {
		return result, fmt.Errorf("unable to get user data location. %v", err)
	}

	u.buf.Seek(1, io.SeekCurrent)

	var userDataLength uint32
	err = binary.Read(u.buf, binary.LittleEndian, &userDataLength)
	if err != nil {
		return result, fmt.Errorf("unable to get user data length. %v", err)
	}

	u.buf.Seek(2, io.SeekCurrent)
	err = binary.Read(u.buf, binary.LittleEndian, &meta.FunctionHash)
	if err != nil {
		return result, fmt.Errorf("unable to get function hash. %v", err)
	}

	u.buf.Seek(1, io.SeekCurrent)
	var dllOffset uint32
	err = binary.Read(u.buf, binary.LittleEndian, &dllOffset)
	if err != nil {
		return result, fmt.Errorf("unable to get dll offset. %v", err)
	}

	dllLength := userDataOffset - dllOffset

	u.buf.Seek(int64(dllOffset)+5, io.SeekStart) // skips remaining bytes of 32-bit bootstrap
	dllBytes := make([]byte, int(dllLength))
	err = binary.Read(u.buf, binary.LittleEndian, &dllBytes)
	if err != nil {
		return result, fmt.Errorf("unable to extract DLL bytes. %v", err)
	}
	result.DLL = dllBytes

	userDataBytes := make([]byte, int(userDataLength))
	err = binary.Read(u.buf, binary.LittleEndian, &userDataBytes)
	if err != nil {
		return result, fmt.Errorf("unable to extract user data. %v", err)
	}
	meta.UserData = string(userDataBytes)
	result.Metadata = meta
	return result, nil
}

func (u *Unpacker) Extract() (*Payload, error) {
	var err error
	arch64, err := u.isAMD64()
	if err != nil {
		return nil, err
	}

	arch32, err := u.isX86()
	if err != nil {
		return nil, err
	}

	var payload Payload
	if arch64 {
		payload, err = u.unpack64bit()
		if err != nil {
			return nil, fmt.Errorf("error while attempting to unpack 64-bit. %v", err)
		}
	} else if arch32 {
		payload, err = u.unpack32bit()
		if err != nil {
			return nil, fmt.Errorf("error while attempting to unpack 32-bit. %v", err)
		}
		payload.Metadata.Arch = common.X86
	} else {
		return nil, fmt.Errorf("unable to determine architecture of input data")
	}

	return &payload, nil
}

func (u *Unpacker) Identified() (string, error) {
	var result string

	payload, err := u.Extract()
	if err != nil {
		return "", fmt.Errorf("error while attempting to extract payload. %v", err)
	}

	result += fmt.Sprintf("[+] CPU Arch: %s\n", common.ArchToString(payload.Metadata.Arch))
	result += fmt.Sprintf("[+] User Data: %s\n", payload.Metadata.UserData)
	result += fmt.Sprintf("[+] Flags:\n")
	result += fmt.Sprintf("\t Clears Header: %s\n", strconv.FormatBool(payload.Metadata.ClearsHeader()))
	result += fmt.Sprintf("\t Clears Memory: %s\n", strconv.FormatBool(payload.Metadata.ClearsMemory()))
	result += fmt.Sprintf("\t Passes Shellcode Base: %s\n", strconv.FormatBool(payload.Metadata.PassesShellcodeBaseToTargetFunction()))
	result += fmt.Sprintf("\t Obfuscates Imports: %s\n", strconv.FormatBool(payload.Metadata.ObfuscatesImports()))

	targetFunc, err := payload.TargetFunction()
	if err != nil {
		return "", fmt.Errorf("could not identify target function. %v", err)
	}
	result += fmt.Sprintf("[*] Target Function: %s", targetFunc)
	return result, nil
}

func (u *Unpacker) CanUnpack() bool {
	var err error
	u.buf.Seek(0, io.SeekStart)

	relJumpComparison := [5]byte{}
	err = binary.Read(u.buf, binary.LittleEndian, &relJumpComparison)
	if err != nil {
		fmt.Printf("Error: %v", err)
		return false
	}

	if relativeJump == relJumpComparison {
		return true
	}
	return false
}

func (u *Unpacker) UnpackToFile(path string) error {
	payload, err := u.Extract()
	if err != nil {
		return fmt.Errorf("failed to unpack to file. %v", err)
	}
	err = os.WriteFile(path, payload.DLL, os.ModePerm)
	if err != nil {
		return fmt.Errorf("failed to write payload to file. %v", err)
	}
	return nil
}
