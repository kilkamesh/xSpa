package core

type Config struct {
	Iface     string
	SPAPort   uint32
	SignKey   [16]byte
	CipherKey [32]byte
	Profiles  map[string]Profile
}

type Profile struct {
	IPv4      string
	SPAPort   uint32
	SignKey   [16]byte
	CipherKey [32]byte
}
