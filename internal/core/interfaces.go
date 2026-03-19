package core

import (
	"context"
)

type EBPFManager interface {
	Attach(ifaceName string) error
	ReadPackets(ctx context.Context) (<-chan SpaPacket, <-chan error, error)
	Authorize(ip uint32, ttlNs uint64) error
	Close() error
}

type Signer interface {
	Sign(data []byte) ([]byte, error)
	Verify(data []byte, signature []byte) bool
}

type Cipher interface {
	Pack(data []byte) ([]byte, []byte, error)
	Unpack(ciphertext []byte, nonce []byte) ([]byte, error)
}
