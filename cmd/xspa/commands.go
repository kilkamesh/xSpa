package main

import (
	"context"
	"fmt"
	"time"
	"xknock/internal/usecases"

	"github.com/spf13/cobra"
)

var cfgPath string
var targetIP string
var knockTTL time.Duration
var runTimeout time.Duration

func init() {
	rootCmd.PersistentFlags().StringVarP(&cfgPath, "config", "c", "~/.xspa/config.json", "path to config file")
	knockCmd.Flags().DurationVarP(&knockTTL, "ttl", "t", 1*time.Hour, "TTL (e.g. 10s, 5m, 1h)")
	knockCmd.Flags().StringVarP(&targetIP, "ip", "i", "", "Target IP for authorization (default: auto-detect)")
	runCmd.Flags().DurationVarP(&runTimeout, "timeout", "d", 0, "Server auto-shutdown timeout (e.g. 5m, 1h)")
	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(knockCmd)
}

var rootCmd = &cobra.Command{
	Use:   "xspa [command]",
	Short: "SPA knocker based on eBPF",
}

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run xSpa server",
	RunE: func(cmd *cobra.Command, args []string) error {
		app, err := bootstrap(cfgPath)
		if err != nil {
			return fmt.Errorf("initialization failed: %w", err)
		}
		defer app.cleanup()

		ctx := cmd.Context()
		if runTimeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, runTimeout)
			defer cancel()
			fmt.Printf("Server will auto-shutdown in %v\n", runTimeout)
		}

		executor := usecases.NewExecuter(app.cfg, app.manager, app.cipher, ctx)

		return executor.Run()
	},
}

var knockCmd = &cobra.Command{
	Use:   "knock [profile_name]",
	Short: "Send SPA packet to a specific profile",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		profileName := args[0]

		app, err := bootstrap(cfgPath)
		if err != nil {
			return err
		}

		profile, ok := app.cfg.Profiles[profileName]
		if !ok {
			return fmt.Errorf("profile '%s' not found in config", profileName)
		}

		knocker := usecases.NewKnocker(app.signerL1, app.cipher)

		fmt.Printf("Knocking to %s (%s:%d) with TTL %ds...\n",
			profileName, profile.IPv4, profile.SPAPort, knockTTL)

		return knocker.Knock(profile.IPv4, profile.SPAPort, knockTTL, targetIP)
	},
}
