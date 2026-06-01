// ward-guard is the background daemon that watches home directory zones and
// enforces the three-tier access policy.
package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/skerve/ward-os/internal/allow"
	"github.com/skerve/ward-os/internal/audit"
	"github.com/skerve/ward-os/internal/config"
	"github.com/skerve/ward-os/internal/guard"
	"github.com/skerve/ward-os/internal/version"
)

var cfgPath string

func main() {
	root := &cobra.Command{
		Use:     "ward-guard",
		Short:   "Background daemon: watches home directory zones and enforces access policy",
		Version: version.String(),
		RunE:    run,
	}
	root.Flags().StringVar(&cfgPath, "config", "", "config file (default: ~/.config/ward-os/ward.yaml)")

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func run(_ *cobra.Command, _ []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	dbPath := config.ExpandHome(cfg.Audit.DBPath)

	auditor, err := audit.Open(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warn: cannot open audit db %s: %v — events will not be persisted\n", dbPath, err)
		auditor = nil
	}
	if auditor != nil {
		defer auditor.Close()
	}

	grants, err := allow.Open(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warn: cannot open allow store: %v — allow-list disabled\n", err)
		grants = nil
	}
	if grants != nil {
		defer grants.Close()
	}

	g, err := guard.New(cfg.Guard, auditor, grants)
	if err != nil {
		return fmt.Errorf("creating guard: %w", err)
	}

	if err := g.AddWatchZones(); err != nil {
		return fmt.Errorf("adding watch zones: %w", err)
	}

	// Periodic maintenance.
	if auditor != nil {
		go func() {
			ticker := time.NewTicker(24 * time.Hour)
			defer ticker.Stop()
			for range ticker.C {
				if cfg.Audit.RetainDays > 0 {
					n, _ := auditor.Purge(cfg.Audit.RetainDays)
					if n > 0 {
						fmt.Printf("audit: purged %d old entries\n", n)
					}
				}
				if grants != nil {
					n, _ := grants.PurgeExpired()
					if n > 0 {
						fmt.Printf("allow: purged %d expired grants\n", n)
					}
				}
			}
		}()
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sig
		fmt.Println("ward-guard: shutting down")
		g.Stop()
	}()

	g.Run()
	return nil
}

func loadConfig() (*config.Config, error) {
	defaultData, _ := os.ReadFile(filepath.Join(
		filepath.Dir(os.Args[0]), "..", "config", "ward.yaml",
	))
	return config.LoadOrDefault(cfgPath, defaultData)
}
