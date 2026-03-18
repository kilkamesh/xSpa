package usecases

import (
	"context"
	"fmt"
	"log/slog"
	"time"
	"xknock/internal/core"
)

type executer struct {
	Config  *core.Config
	manager core.EBPFManager
	chiper  core.Cipher
	ctx     context.Context
}

func NewExecuter(config *core.Config, ebpf core.EBPFManager, chiper core.Cipher, ctx context.Context) *executer {
	return &executer{
		Config:  config,
		manager: ebpf,
		chiper:  chiper,
		ctx:     ctx,
	}
}

func (e *executer) ensurePacket(p core.SpaPacketPayload) bool {
	nowWall := uint64(time.Now().UnixNano())
	const maxDrift = uint64(20 * time.Second)
	const futureDrift = uint64(5 * time.Second)

	if nowWall > p.Timestamp && (nowWall-p.Timestamp) > maxDrift {
		slog.Warn("stale packet", "diff_sec", (nowWall-p.Timestamp)/1e9)
		return false
	}
	if p.Timestamp > nowWall+futureDrift {
		slog.Warn("packet from future", "timestamp", p.Timestamp)
		return false
	}
	return true
}

func (e *executer) Run() error {
	if err := e.manager.Attach(e.Config.Iface); err != nil {
		return fmt.Errorf("failed to start filtering: %w", err)
	}
	packets, errs, err := e.manager.ReadPackets(e.ctx)
	if err != nil {
		return fmt.Errorf("could not start reader: %w", err)
	}
	slog.Info("xSpa is active and protecting your ports.")
	for {
		select {
		case <-e.ctx.Done():
			slog.Info("shutting down xSpa...")
			return nil
		case err := <-errs:
			slog.Error("read error", "err", err)
		case p := <-packets:
			encrypted, err := e.chiper.Unpack(p.PayloadTag[:], p.Nonce[:])

			if err != nil {
				slog.Error("authorize failed", "err", err)
				continue
			}

			var pl core.SpaPacketPayload
			pl.Decode(encrypted)

			if !e.ensurePacket(pl) {
				continue
			}

			requestedTTL := uint64(pl.TTL) * uint64(time.Second)

			if err := e.manager.Authorize(pl.TargetIP, requestedTTL); err != nil {
				slog.Error("authorize failed", "err", err)
				continue
			}

			slog.Info("successfully authorized", "ip", pl.TargetIP, "ttl", requestedTTL/1e9)
		}
	}
}
