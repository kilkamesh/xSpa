package main

import (
	"fmt"
	"xknock/internal/core"
	"xknock/internal/infra/config/json"
	"xknock/internal/infra/crypto/chacha"
	"xknock/internal/infra/crypto/siphash"
	"xknock/internal/infra/ebpf"
)

type App struct {
	cfg      *core.Config
	manager  core.EBPFManager
	signerL1 core.Signer
	cipher   core.Cipher
	cleanup  func()
}

func bootstrap(cfgPath string) (*App, error) {
	cfg, err := json.Load(cfgPath)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}

	manager, err := ebpf.NewManager(cfg.SPAPort, cfg.SignKey)
	if err != nil {
		return nil, fmt.Errorf("ebpf: %w", err)
	}
	signerL1 := siphash.NewSigner(cfg.SignKey)
	cipher, err := chacha.NewCipher(cfg.CipherKey[:])
	cleanup := func() {
		manager.Close()
	}
	return &App{
		cfg:      cfg,
		manager:  manager,
		signerL1: signerL1,
		cipher:   cipher,
		cleanup:  cleanup,
	}, nil
}
