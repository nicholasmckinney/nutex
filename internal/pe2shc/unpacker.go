package pe2shc

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"nutextractor/internal/common"
)

var RedirCodeMultiArch = []byte{
	0x4d, 0x5a, 0x45, 0x52, 0xe8, 0x0, 0x0, 0x0, 0x0,
	0x5b, 0x48, 0x83, 0xeb, 0x09, 0x53, 0x48, 0x81, // bytes 9-14 differentiating factor
	0xc3,
	0xff, 0xff, 0xff, 0xff, // replaced with EXE size
	0xff, 0xd3, 0xc3,
}

var RedirCode32 = []byte{
	0x4d, 0x5a, 0x45, 0x52, 0xe8, 0x0, 0x0, 0x0, 0x0,
	0x58, 0x83, 0xe8, 0x09, 0x50, 0x05,
	0xff, 0xff, 0xff, 0xff, // replaced with EXE size
	0xff, 0xd0, 0xc3,
}

var RedirCode64 = []byte{
	0x4d, 0x5a, 0x45, 0x52, 0xe8, 0x0, 0x0, 0x0, 0x0,
	0x59, 0x48, 0x83, 0xe9, 0x09, 0x48,
	0x8b, 0xc1, 0x48, 0x05,
	0xff, 0xff, 0xff, 0xff, // replaced with EXE size
	0xff, 0xd0, 0xc3,
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
	PE []byte
}

func New(content []byte) *Unpacker {
	return &Unpacker{buf: bytes.NewReader(content)}
}

func (u *Unpacker) Name() string {
	return "Hasherezade pe_to_shellcode"
}

func (u *Unpacker) Identified() (string, error) {
	arch, err := u.arch()
	if err != nil {
		return "", fmt.Errorf("unable to identify architecture of shellcode. %v", err)
	}

	var result string
	result += fmt.Sprintf("[+] CPU Arch: %s\n", common.ArchToString(arch))
	return result, nil
}

func (u *Unpacker) arch() (common.CPUArch, error) {
	var err error

	samples := make(map[common.CPUArch][]byte)
	samples[common.MultiArch] = RedirCodeMultiArch
	samples[common.AMD64] = RedirCode64
	samples[common.X86] = RedirCode32

	for sampleArch, sampleBytes := range samples {
		u.buf.Seek(0, io.SeekStart)
		fileBytes := make([]byte, len(sampleBytes))
		err = binary.Read(u.buf, binary.LittleEndian, &fileBytes)
		if err != nil {
			continue
		}
		if bytes.Equal(fileBytes[9:14], sampleBytes[9:14]) {
			return sampleArch, nil
		}
	}
	return common.Unknown, fmt.Errorf("unable to identify architecture of shellcode")
}

func (u *Unpacker) CanUnpack() bool {
	_, err := u.arch()
	if err != nil {
		return false
	}
	return true
}

func (u *Unpacker) UnpackToFile(path string) error {
	return fmt.Errorf("[+] File does not need to be unpacked. Even compiled to shellcode, it is a valid PE")
}
