package usecases

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"time"
	"xknock/internal/core"
	"xknock/internal/infra/network"
)

type Knocker struct {
	signerL1 core.Signer
	chiper   core.Cipher
}

func NewKnocker(signerL1 core.Signer, chiper core.Cipher) *Knocker {
	return &Knocker{signerL1: signerL1, chiper: chiper}
}

func (k *Knocker) buildPacket(targetIP uint32, ttl uint32) ([]byte, error) {
	pld := core.SpaPacketPayload{
		TTL:       ttl,
		Timestamp: uint64(time.Now().UnixNano()),
		TargetIP:  targetIP,
	}
	var pkt core.SpaPacket

	cryptoNonce, tag, err := k.chiper.Pack(pld.Encode())
	if err != nil {
		return nil, err
	}
	copy(pkt.PayloadTag[:], tag)
	copy(pkt.Nonce[:], cryptoNonce)

	sig1, err := k.signerL1.Sign(append(cryptoNonce, tag...))
	pkt.L1Hash = binary.LittleEndian.Uint64(sig1)

	return pkt.Encode(), nil
}

func (k *Knocker) resolveIp(ip string) (net.IP, error) {
	var err error
	if ip == "" {
		ip, err = network.GetPublicIP()
	}
	return net.ParseIP(ip), err
}
func (k *Knocker) Knock(address string, port uint32, ttl time.Duration, ip string) error {
	targetIP, err := k.resolveIp(ip)
	slog.Info(fmt.Sprintf("target ip: %s", targetIP))
	dst := net.JoinHostPort(address, fmt.Sprintf("%d", port))
	conn, err := net.Dial("udp", dst)
	if err != nil {
		return fmt.Errorf("failed to dial: %w", err)
	}
	defer conn.Close()
	payload, err := k.buildPacket(network.IpToUint32(targetIP.String()), uint32(ttl.Seconds()))
	_, err = conn.Write(payload)
	return err
}
