package main

import (
	"fmt"
	"xknock/internal/core"
	"xknock/internal/infra/config/json"
	"xknock/internal/infra/crypto/chacha"
	"xknock/internal/infra/crypto/siphash"
)

type App struct {
	cfg *core.Config

	signerL1 core.Signer
	cipher   core.Cipher
}

func bootstrap(cfgPath string) (*App, error) {
	cfg, err := json.Load(cfgPath)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}

	signerL1 := siphash.NewSigner(cfg.SignKey)
	cipher, err := chacha.NewCipher(cfg.CipherKey[:])

	return &App{
		cfg: cfg,

		signerL1: signerL1,
		cipher:   cipher,
	}, nil
}
