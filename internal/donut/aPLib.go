// Copyright (C) 2019-2021 Hatching B.V.
// All rights reserved.

// pulled from: https://github.com/hatching/aplib/blob/main/decompress.go

package donut

import (
	"bufio"
	"bytes"
	"io"
)

var DecompressMaxSize = 4 * 1024 * 1024

type aPdecompress struct {
	src      *bufio.Reader
	dst      bytes.Buffer
	tag      uint8
	bitcount uint32
}

func (a *aPdecompress) getBit() *int {
	if a.bitcount == 0 {
		ch, err := a.src.ReadByte()
		if err != nil {
			return nil
		}
		a.tag = ch
		a.bitcount = 7
	} else {
		a.bitcount--
	}

	bit := int((a.tag >> 7) & 1)
	a.tag <<= 1
	return &bit
}

func (a *aPdecompress) getGamma() *uint32 {
	result := uint32(1)
	cont := true
	for cont {
		if result&0x80000000 != 0 {
			return nil
		}

		if bit := a.getBit(); bit == nil {
			return nil
		} else {
			result += result + uint32(*bit)
		}

		if bit := a.getBit(); bit == nil {
			return nil
		} else {
			cont = *bit != 0
		}
	}
	return &result
}

func Decompress2(r io.Reader) []byte {
	a := aPdecompress{
		src: bufio.NewReader(r),
	}

	r0, lwm, done := 0xffffffff, false, false

	ch, err := a.src.ReadByte()
	if err != nil {
		return nil
	}

	a.dst.Write([]byte{ch})

	for !done {
		if bit := a.getBit(); bit == nil {
			return nil
		} else if *bit != 0 {
			if bit := a.getBit(); bit == nil {
				return nil
			} else if *bit != 0 {
				if bit := a.getBit(); bit == nil {
					return nil
				} else if *bit != 0 {
					var offs int
					for i := 4; i != 0; i-- {
						if bit := a.getBit(); bit == nil {
							return nil
						} else {
							offs += offs + *bit
						}
					}
					if offs != 0 {
						if offs > a.dst.Len() {
							return nil
						}
						ch := a.dst.Bytes()[a.dst.Len()-offs]
						a.dst.Write([]byte{ch})
					} else {
						a.dst.Write([]byte{0})
					}
					lwm = false
				} else {
					ch, err := a.src.ReadByte()
					if err != nil {
						return nil
					}

					offs := int(ch)

					length := 2 + (offs & 1)
					offs >>= 1

					if offs != 0 {
						if offs > a.dst.Len() {
							return nil
						}

						for ; length != 0; length-- {
							ch := a.dst.Bytes()[a.dst.Len()-offs]
							a.dst.Write([]byte{ch})
						}
					} else {
						done = true
					}
					r0 = offs
					lwm = true
				}
			} else {
				if offs := a.getGamma(); offs == nil {
					return nil
				} else if lwm == false && *offs == 2 {
					*offs = uint32(r0)

					if length := a.getGamma(); length == nil {
						return nil
					} else if a.dst.Len()+int(*length) > DecompressMaxSize {
						return nil
					} else if int(*offs) > a.dst.Len() {
						return nil
					} else {
						for ; *length != 0; *length -= 1 {
							ch := a.dst.Bytes()[a.dst.Len()-int(*offs)]
							a.dst.Write([]byte{ch})
						}
					}
				} else {
					if lwm == false {
						*offs -= 3
					} else {
						*offs -= 2
					}

					if *offs > 0x00fffffe {
						return nil
					}

					*offs <<= 8

					ch, err := a.src.ReadByte()
					if err != nil {
						return nil
					}
					*offs += uint32(ch)

					if length := a.getGamma(); length == nil {
						return nil
					} else if a.dst.Len()+int(*length) > DecompressMaxSize {
						return nil
					} else {
						if *offs >= 32000 {
							*length++
						}
						if *offs >= 1280 {
							*length++
						}
						if *offs < 128 {
							*length += 2
						}
						if *offs == 0 || int(*offs) > a.dst.Len() {
							return nil
						}
						for ; *length != 0; *length -= 1 {
							ch := a.dst.Bytes()[a.dst.Len()-int(*offs)]
							a.dst.Write([]byte{ch})
						}
						r0 = int(*offs)
					}
				}
				lwm = true
			}
		} else {
			ch, err := a.src.ReadByte()
			if err != nil {
				return nil
			}
			a.dst.Write([]byte{ch})
			lwm = false
		}
	}
	return a.dst.Bytes()
}

func Decompress(buf []byte) []byte {
	return Decompress2(bytes.NewReader(buf))
}
