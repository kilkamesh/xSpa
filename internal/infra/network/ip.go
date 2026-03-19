package network

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

func GetPublicIP() (string, error) {
	services := []string{
		"https://ifconfig.me",
		"https://api.ipify.org",
	}

	client := http.Client{
		Timeout: 5 * time.Second,
	}

	for _, url := range services {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}

		req.Header.Set("User-Agent", "curl/7.81.0")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err == nil && resp.StatusCode == http.StatusOK {
			return strings.TrimSpace(string(body)), nil
		}
	}

	return "", fmt.Errorf("could not retrieve public IP from any service")
}

func IpToUint32(ipStr string) uint32 {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return 0
	}
	return binary.LittleEndian.Uint32(ip)
}

func SwapUint32(n uint32) uint32 {
	return ((n & 0xFF000000) >> 24) |
		((n & 0x00FF0000) >> 8) |
		((n & 0x0000FF00) << 8) |
		((n & 0x000000FF) << 24)
}
