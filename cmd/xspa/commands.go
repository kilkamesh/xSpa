package main

import (
	"fmt"
	"time"
	"xknock/internal/usecases"

	"github.com/spf13/cobra"
)

var cfgPath string
var targetIP string
var knockTTL time.Duration

func init() {
	rootCmd.PersistentFlags().StringVarP(&cfgPath, "config", "c", "~/.xspa/config.json", "path to config file")
	knockCmd.Flags().DurationVarP(&knockTTL, "ttl", "t", 1*time.Hour, "TTL (e.g. 10s, 5m, 1h)")
	knockCmd.Flags().StringVarP(&targetIP, "ip", "i", "", "Target IP for authorization (default: auto-detect)")
	rootCmd.AddCommand(knockCmd)
}

var rootCmd = &cobra.Command{
	Use:   "xspa [command]",
	Short: "SPA knocker based on eBPF",
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
