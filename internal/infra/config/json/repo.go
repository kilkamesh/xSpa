package json

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"xknock/internal/core"
)

func Load(path string) (*core.Config, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := generateDefaultConfig(path); err != nil {
			return nil, fmt.Errorf("failed to generate default config: %w", err)
		}
		fmt.Printf("Generated default config at %s. Please edit it.\n", path)
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var cfg Config
	if err := json.NewDecoder(file).Decode(&cfg); err != nil {
		return nil, err
	}

	return cfg.toEntity()
}

func generateDefaultConfig(path string) error {
	sk := make([]byte, 16)
	cp := make([]byte, 32)
	rand.Read(sk)
	rand.Read(cp)

	defaultCfg := Config{
		Server: Server{
			Iface:     "eth0",
			SPAPort:   55555,
			SignKey:   hex.EncodeToString(sk),
			CipherKey: hex.EncodeToString(cp),
		},
		Profiles: make(map[string]Profile),
	}

	data, err := json.MarshalIndent(defaultCfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
