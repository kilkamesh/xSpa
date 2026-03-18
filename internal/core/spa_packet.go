package core

import (
	"encoding/binary"
	"errors"
	"fmt"
)

type SpaPacketPayload struct {
	TTL       uint32
	Timestamp uint64
	TargetIP  uint32
}

func (p *SpaPacketPayload) Encode() []byte {
	buf := make([]byte, 16) // 4 + 8 + 4
	binary.LittleEndian.PutUint32(buf[0:4], p.TTL)
	binary.LittleEndian.PutUint64(buf[4:12], p.Timestamp)
	binary.BigEndian.PutUint32(buf[12:16], p.TargetIP)
	return buf
}

func (p *SpaPacketPayload) Decode(data []byte) error {
	if len(data) < 16 {
		return errors.New("payload too short")
	}
	p.TTL = binary.LittleEndian.Uint32(data[0:4])
	p.Timestamp = binary.LittleEndian.Uint64(data[4:12])
	p.TargetIP = binary.BigEndian.Uint32(data[12:16])
	return nil
}

type SpaPacket struct {
	L1Hash     uint64
	Nonce      [24]byte
	PayloadTag [32]byte
}

const PacketSize = 64

func (p *SpaPacket) Decode(data []byte) error {
	if len(data) < PacketSize {
		return fmt.Errorf("invalid packet size: %d, expected %d", len(data), PacketSize)
	}
	p.L1Hash = binary.LittleEndian.Uint64(data[0:8])
	copy(p.Nonce[:], data[8:32])
	copy(p.PayloadTag[:], data[32:64])
	return nil
}

func (p *SpaPacket) Encode() []byte {
	buf := make([]byte, PacketSize)

	binary.LittleEndian.PutUint64(buf[0:8], p.L1Hash)
	copy(buf[8:32], p.Nonce[:])
	copy(buf[32:64], p.PayloadTag[:])

	return buf
}
