package chacha

import (
	"crypto/cipher"
	"crypto/rand"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

type Cipher struct {
	aead cipher.AEAD
}

func NewCipher(key []byte) (*Cipher, error) {
	block, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return &Cipher{aead: block}, nil
}

func (c *Cipher) Pack(data []byte) ([]byte, []byte, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	encrypted := c.aead.Seal(nil, nonce, data, nil)
	return nonce, encrypted, nil
}

func (c *Cipher) Unpack(ciphertext []byte, nonce []byte) ([]byte, error) {
	return c.aead.Open(nil, nonce, ciphertext, nil)
}
