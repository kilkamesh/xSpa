package ebpf

import (
	"context"
	"fmt"
	"net"
	"xknock/internal/core"
	"xknock/internal/infra/ebpf/xdp"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

type Manager struct {
	objs xdp.XspaObjects
	link link.Link
}

func NewManager(spaPort uint32, sipk [16]byte) (*Manager, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, err
	}

	spec, err := xdp.LoadXspa()
	if err != nil {
		return nil, err
	}

	spec.Variables["SPA_PORT"].Set(spaPort)
	spec.Variables["SIPHASH_KEYS"].Set(sipk)

	var objs xdp.XspaObjects
	err = spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: "/sys/fs/bpf",
		},
	})

	if err != nil {
		return nil, fmt.Errorf("load and pin: %w", err)
	}

	return &Manager{objs: objs}, nil
}

func (m *Manager) Attach(ifaceName string) error {
	if m.link != nil {
		return fmt.Errorf("already attached")
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("interface %s: %w", ifaceName, err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   m.objs.XspaMain,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		return fmt.Errorf("attach XDP: %w", err)
	}

	m.link = l
	return nil
}

func (m *Manager) ReadPackets(ctx context.Context) (<-chan core.SpaPacket, <-chan error, error) {
	reader, err := ringbuf.NewReader(m.objs.SpaRingbuf)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create ringbuf reader: %w", err)
	}

	out := make(chan core.SpaPacket)
	errs := make(chan error)

	go func() {
		defer reader.Close()
		defer close(out)
		defer close(errs)

		for {
			select {
			case <-ctx.Done():
				return
			default:
				rec, err := reader.Read()
				if err != nil {
					return
				}

				var packet core.SpaPacket
				if err := packet.Decode(rec.RawSample); err != nil {
					errs <- err
					continue
				}

				out <- packet
			}
		}
	}()

	return out, errs, nil
}

func (m *Manager) Authorize(ip uint32, ttlNs uint64) error {
	var ts unix.Timespec
	err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	if err != nil {
		return fmt.Errorf("failed to get monotonic clock: %w", err)
	}

	nowNs := uint64(ts.Sec)*1e9 + uint64(ts.Nsec)
	expiry := nowNs + ttlNs

	return m.objs.WhitelistLru.Put(ip, expiry)
}

func (m *Manager) Close() error {
	var errs []error

	if m.link != nil {
		if err := m.link.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close link: %w", err))
		}
	}

	if err := m.objs.Close(); err != nil {
		errs = append(errs, fmt.Errorf("close objects: %w", err))
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors during cleanup: %v", errs)
	}
	return nil
}
