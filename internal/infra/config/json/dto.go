package json

import (
	"encoding/hex"
	"strings"
	"xknock/internal/core"
	"xknock/internal/infra/config"
)

type Server struct {
	Iface           string `json:"iface"`
	SPAPort         uint32 `json:"spa_port"`
	SignKey         string `json:"sign_key"`
	SignKeySecret   string `json:"sign_key_file"`
	CipherKey       string `json:"chiper_key"`
	CipherKeySecret string `json:"chiper_key_file"`
}

type Config struct {
	Server   Server             `json:"server"`
	Profiles map[string]Profile `json:"profiles"`
}

func (c *Config) toEntity() (*core.Config, error) {
	config.FillFromEnvs(c.Server, config.CONFIG_ENV_PREFIX)
	config.ExpandSecrets(c.Server)

	sk, _ := hex.DecodeString(c.Server.SignKey)
	ck, _ := hex.DecodeString(c.Server.CipherKey)

	res := &core.Config{
		Iface:     c.Server.Iface,
		SPAPort:   c.Server.SPAPort,
		SignKey:   [16]byte(sk),
		CipherKey: [32]byte(ck),
		Profiles:  make(map[string]core.Profile),
	}

	for name, pJson := range c.Profiles {
		pEntity, _ := pJson.toEntity(name)
		res.Profiles[name] = *pEntity
	}

	return res, nil
}

type Profile struct {
	IPv4            string `json:"ipv4"`
	SPAPort         uint32 `json:"spa_port"`
	SignKey         string `json:"sign_key"`
	SignKeySecret   string `json:"sign_key_file"`
	CipherKey       string `json:"chiper_key"`
	CipherKeySecret string `json:"chiper_key_file"`
}

func (p *Profile) toEntity(name string) (*core.Profile, error) {
	config.FillFromEnvs(p, config.PROFILE_ENV_PREFIX+"_"+strings.ToUpper(name))
	config.ExpandSecrets(p)

	sk, _ := hex.DecodeString(p.SignKey)
	ck, _ := hex.DecodeString(p.CipherKey)

	return &core.Profile{
		IPv4:      p.IPv4,
		SPAPort:   p.SPAPort,
		SignKey:   [16]byte(sk),
		CipherKey: [32]byte(ck),
	}, nil
}
