//go:build linux

package main

import (
	"context"
	"fmt"
	"time"
	"xknock/internal/infra/ebpf"
	"xknock/internal/usecases"

	"github.com/spf13/cobra"
)

var runTimeout time.Duration

func init() {
	runCmd.Flags().DurationVarP(&runTimeout, "timeout", "d", 0, "Server auto-shutdown timeout (e.g. 5m, 1h)")
	rootCmd.AddCommand(runCmd)
}

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run xSpa server",
	RunE: func(cmd *cobra.Command, args []string) error {
		app, err := bootstrap(cfgPath)
		if err != nil {
			return fmt.Errorf("initialization failed: %w", err)
		}
		manager, err := ebpf.NewManager(app.cfg.SPAPort, app.cfg.SignKey)
		if err != nil {
			return fmt.Errorf("ebpf: %w", err)
		}
		defer manager.Close()

		ctx := cmd.Context()
		if runTimeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, runTimeout)
			defer cancel()
			fmt.Printf("Server will auto-shutdown in %v\n", runTimeout)
		}

		executor := usecases.NewExecuter(app.cfg, manager, app.cipher, ctx)

		return executor.Run()
	},
}
