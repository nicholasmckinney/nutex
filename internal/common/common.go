package common

type Unpacker interface {
	Name() string
	Identified() (string, error)
	CanUnpack() bool
	UnpackToFile(string) error
}

type UnpackerFactory interface {
	Build([]byte) Unpacker
}

type CPUArch int

const (
	AMD64 CPUArch = iota
	X86
	MultiArch
	Unknown
)

func ArchToString(arch CPUArch) string {
	if arch == AMD64 {
		return "AMD64"
	} else if arch == X86 {
		return "X86"
	} else if arch == MultiArch {
		return "x86 + AMD64"
	}
	return "UNKNOWN"
}
