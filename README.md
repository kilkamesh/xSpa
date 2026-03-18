# xSpa
![alt text](https://img.shields.io/badge/license-GPLv3-blue.svg)
![alt text](https://img.shields.io/badge/go-1.21%2B-blue)
![alt text](https://img.shields.io/badge/platform-linux-lightgrey)

![](icon.png)

xSpa is a minimalist implementation of Single Packet Authorization (SPA) based on eBPF/XDP filtering. The system blocks all incoming packets at the network driver level, preventing them from reaching the Linux kernel network stack until successful authorization.

Unlike traditional solutions (e.g., `fwknop`) that rely on `iptables` or `libpcap`, xSpa is inherently resilient to DDoS attacks because filtering occurs at the earliest possible stage of traffic processing.

### Key Features

1.  **XDP Filtering**: Packets are dropped before `sk_buff` allocation, ensuring minimal latency and CPU overhead.
    
    **Two-level verification:**
    *   **L1 (Kernel Space):** Fast SipHash verification to protect against flood attacks, bypassing User Space.
    *   **L2 (User Space):** Full cryptographic validation using ChaCha20-Poly1305.

2.  **Anti-Replay**: Built-in timestamp validation to protect against replay attacks.

3.  **Zero Visibility**: Ports remain completely closed to scanners (nmap, etc.) until a valid SPA packet is received.

## xSpa Packet Structure (64 bytes)
This diagram visualizes the binary layout of the data transmitted over the network.

```mermaid
graph TD
    subgraph SpaPacket [SpaPacket - 64 bytes]
        L1Hash[L1Hash: uint64 <br/> 0-8 bytes <br/> SipHash2-4]
        Nonce[Nonce: 24 bytes <br/> 8-32 bytes <br/> XChaCha20 Nonce]
        PayloadTag[PayloadTag: 32 bytes <br/> 32-64 bytes <br/> Encrypted Payload + Tag]
    end

    subgraph DecryptedPayload [Decrypted  - 16 bytes]
        TTL[TTL: uint32 <br/> 4 bytes]
        TS[Timestamp: uint64 <br/> 8 bytes]
        IP[TargetIP: uint32 <br/> 4 bytes]
    end

    PayloadTag -.->|Decrypted with Nonce| DecryptedPayload
```

## Packet Flow
This diagram shows the separation of responsibilities between the Kernel (XDP) and User Space (Go).

```mermaid
sequenceDiagram
    participant Client as Client (knock)
    participant XDP as Kernel (XDP Program)
    participant RB as eBPF Ring Buffer
    participant Go as User Space (Go Server)
    participant Map as BPF Map (whitelist_lru)

    Client->>XDP: UDP Packet (64 bytes)
    
    Note over XDP: Primary Verification (L1Hash)
    XDP->>XDP: SipHash2-4(Packet[8:64], Key)
    
    alt Hash Mismatch
        XDP-->>Client: XDP_DROP (Packet Dropped)
    else Hash Match
        XDP->>RB: bpf_ringbuf_output(Packet)
        XDP-->>Client: XDP_DROP (Packet Dropped)
    end

    RB->>Go: Receive Raw Data
    
    Note over Go: Decryption & Validation
    Go->>Go: ChaCha20-Poly1305 Decrypt(Nonce, PayloadTag)
    Go->>Go: Timestamp Check (Anti-Replay)
    Go->>Go: TTL & TargetIP Check
    
    alt Validation Failed
        Go--xGo: Log Warning & Drop
    else Validation Success
        Go->>Map: bpf_map_update_elem(src_ip, expiry)
        Note over Map: IP Whitelisted for TTL duration
    end
```

## Installation & Setup

### Environment Requirements
*   Linux Kernel version 5.8 or higher (Ring Buffer support required).
*   `clang`, `llvm`, and `libbpf-dev` installed.
*   Go version 1.21+.

### Building the Project
1.  **Generate eBPF objects:**
    ```bash
    go generate ./internal/infra/ebpf/xdp/gen.go
    ```

2.  **Compile the binary:**
    ```bash
    go build -o xspa ./cmd/xspa
    ```

## Configuration
xSpa supports hierarchical configuration (JSON -> ENV -> Secrets). Minimal `config.json` example:

```json
{
  "server": {
    "iface": "eth0",
    "spa_port": 55555,
    "sign_key": "your-32-char-siphash-key",
    "cipher_key": "your-64-char-chacha-key-in-hex"
  },
  "profiles": {
    "prod": {
      "ipv4": "1.2.3.4",
      "spa_port": 55555,
      "sign_key": "your-32-char-siphash-key",
      "cipher_key": "your-64-char-chacha-key-in-hex"
    }
  }
}
```
All environment variables can be set using the `XSPA_` prefix.

Profiles can also be defined via ENV, for example: `XSPA_PROFILES_<NAME>_SPA_PORT`.

## Usage

### Running the Server
The server must be run with superuser privileges to load the XDP program into the kernel:
```bash
sudo ./xspa run -c config.json
```

### Sending an Authorization Packet (Knock)
To request access from the client side:
```bash
./xspa knock prod -i <your_public_ip> -c config.json
```

## Security
*   **XDP_DROP**: The system operates on a "drop-all" principle. Even a valid SPA packet is dropped after processing to leave no trace of network activity.
*   **SipHash**: Using SipHash at the kernel level protects User Space from resource exhaustion attacks (CPU-DoS).
*   **AEAD**: Using ChaCha20-Poly1305 guarantees both data confidentiality and integrity.