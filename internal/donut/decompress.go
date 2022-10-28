package donut

import (
	"fmt"
	"syscall"
	"unsafe"
)

// https://github.com/TheWover/donut/blob/dafea1702ce2e71d5139c4d583627f7ee740f3ae/loader/loader.c#L237-L301

const COMPRESSION_ENGINE_MAXIMUM = 0x0100

var (
	ntoskrnl            = syscall.MustLoadDLL("ntdll.dll")
	RtlDecompressBuffer = ntoskrnl.MustFindProc("RtlDecompressBuffer")
	// RtlGetCompressionWorkSpaceSize https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlgetcompressionworkspacesize
	RtlGetCompressionWorkSpaceSize = ntoskrnl.MustFindProc("RtlGetCompressionWorkSpaceSize")
)

// DecompressBuffer the input data given the size of the decompressed data (dSize) and the compression engine (algorithm)
func DecompressBuffer(algorithm CompressionEngine, dSize uint32, data []byte) ([]byte, error) {
	var result []byte

	if algorithm == NoCompression {
		return data, nil
	}

	if algorithm != APLib {
		result = make([]byte, dSize+uint32(unsafe.Sizeof(module{})))
		compressionAlgo := (int(algorithm) - 1) | COMPRESSION_ENGINE_MAXIMUM

		var bufferWorkSpaceSize uint32
		var fragmentWorkSpaceSize uint32
		var finalUncompressedSize uint32

		nts, _, _ := RtlGetCompressionWorkSpaceSize.Call(uintptr(compressionAlgo),
			uintptr(unsafe.Pointer(&bufferWorkSpaceSize)),
			uintptr(unsafe.Pointer(&fragmentWorkSpaceSize)),
		)

		if nts != 0 {
			return result, fmt.Errorf("failed to create compression work space")
		}

		nts, _, _ = RtlDecompressBuffer.Call(uintptr(compressionAlgo),
			uintptr(unsafe.Pointer(&result[0])),
			uintptr(len(result)),
			uintptr(unsafe.Pointer(&data[0])),
			uintptr(len(data)),
			uintptr(unsafe.Pointer(&finalUncompressedSize)),
		)

		if nts != 0 {
			return result, fmt.Errorf("failed to decompress buffer")
		}

		return result, nil
	}

	// compression is aPLib
	result = Decompress(data)
	return result, nil
}
