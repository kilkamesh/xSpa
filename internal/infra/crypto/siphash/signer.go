package siphash

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/bits"
)

type Signer struct {
	k0 []byte
	k1 []byte
}

func NewSigner(key [16]byte) *Signer {
	return &Signer{k0: key[:8], k1: key[8:]}
}

func (s *Signer) Sign(data []byte) ([]byte, error) {
	fmt.Printf("DEBUG GO: Key0: %x, Key1: %x\n", s.k0, s.k1)
	return SipHash24b(data, s.k0, s.k1), nil
}

func (s *Signer) Verify(data []byte, signature []byte) bool {
	expected, err := s.Sign(data)
	if err != nil {
		return false
	}
	return bytes.Equal(expected, signature)
}

func SipHash24b(data []byte, k0 []byte, k1 []byte) []byte {
	key0 := binary.LittleEndian.Uint64(k0)
	key1 := binary.LittleEndian.Uint64(k1)
	fmt.Printf("DEBUG GO: Key0: %x, Key1: %x\n", key0, key1)
	v0, v1, v2, v3 := uint64(0x736f6d6570736575)^key0, uint64(0x646f72616e646f6d)^key1, uint64(0x6c7967656e657261)^key0, uint64(0x7465646279746573)^key1
	fmt.Printf("DEBUG GO: v0: %x, v1: %x, v2: %x\n, v3: %x\n", v0, v1, v2, v3)

	sipRound := func() {
		v0 += v1
		v1 = bits.RotateLeft64(v1, 13)
		v1 ^= v0
		v0 = bits.RotateLeft64(v0, 32)
		v2 += v3
		v3 = bits.RotateLeft64(v3, 16)
		v3 ^= v2
		v0 += v3
		v3 = bits.RotateLeft64(v3, 21)
		v3 ^= v0
		v2 += v1
		v1 = bits.RotateLeft64(v1, 17)
		v1 ^= v2
		v2 = bits.RotateLeft64(v2, 32)
	}

	m0, m1, m2 := binary.LittleEndian.Uint64(data[0:8]), binary.LittleEndian.Uint64(data[8:16]), binary.LittleEndian.Uint64(data[16:24])
	fmt.Printf("DEBUG GO: m0: %x, m1: %x, m2: %x\n", m0, m1, m2)
	v3 ^= m0
	sipRound()
	sipRound()
	v0 ^= m0
	v3 ^= m1
	sipRound()
	sipRound()
	v0 ^= m1
	v3 ^= m2
	sipRound()
	sipRound()
	v0 ^= m2

	b := uint64(24) << 56
	v3 ^= b
	sipRound()
	sipRound()
	v0 ^= b

	v2 ^= 0xff
	sipRound()
	sipRound()
	sipRound()
	sipRound()

	res := v0 ^ v1 ^ v2 ^ v3
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, res)
	return buf
}
