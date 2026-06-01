package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Vault  VaultConfig  `yaml:"vault"`
	Guard  GuardConfig  `yaml:"guard"`
	Shell  ShellConfig  `yaml:"shell"`
	Audit  AuditConfig  `yaml:"audit"`
	Ignore IgnoreConfig `yaml:"ignore"`
}

type VaultConfig struct {
	Name               string `yaml:"name"`
	Size               string `yaml:"size"`
	VolumeLabel        string `yaml:"volume_label"`
	MountPoint         string `yaml:"mount_point"`
	AutoUnmountMinutes int    `yaml:"auto_unmount_minutes"`
}

type GuardConfig struct {
	// Zones define the three-tier protection model for the home directory.
	// Each zone has a path, a tier, and an on_violation policy.
	// The guard also auto-discovers dotfolders at ~ and adds them as tier-2.
	Zones                []Zone     `yaml:"zones"`
	WhitelistedProcesses []string   `yaml:"whitelisted_processes"`
	OnViolation          string     `yaml:"on_violation"`
	PathRules            []PathRule `yaml:"path_rules"`
	NotificationTitle    string     `yaml:"notification_title"`
	// WatchPaths is kept for backward compatibility but zones is preferred.
	WatchPaths []string `yaml:"watch_paths"`
}

// Zone is a named, tiered protection area.
type Zone struct {
	Path           string `yaml:"path"`
	Tier           int    `yaml:"tier"` // 1=vault(no override), 2=protected(allow-list ok), 3=watched(alert only)
	OnViolation    string `yaml:"on_violation"`
	DotfoldersOnly bool   `yaml:"dotfolders_only"` // if true, only watch ~/.<name> entries under Path
}

// PathRule overrides the default on_violation policy for a specific path.
type PathRule struct {
	Path        string `yaml:"path"`
	OnViolation string `yaml:"on_violation"`
}

type ShellConfig struct {
	StripEnvPrefixes []string `yaml:"strip_env_prefixes"`
	StripEnvVars     []string `yaml:"strip_env_vars"`
	AgentHome        string   `yaml:"agent_home"`
	LogCommands      bool     `yaml:"log_commands"`
}

type AuditConfig struct {
	DBPath      string `yaml:"db_path"`
	RetainDays  int    `yaml:"retain_days"`
}

type IgnoreConfig struct {
	CursorEntries []string `yaml:"cursor_entries"`
}

// DefaultPath returns the default config file location.
func DefaultPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "ward-os", "ward.yaml")
}

// Load reads the config file at path, expanding ~ in all path fields.
func Load(path string) (*Config, error) {
	if path == "" {
		path = DefaultPath()
	}
	path = ExpandHome(path)

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	cfg.expand()
	return &cfg, nil
}

// LoadOrDefault loads the user config if it exists, otherwise uses the
// bundled default config embedded at compile time.
func LoadOrDefault(path string, defaultData []byte) (*Config, error) {
	if path == "" {
		path = DefaultPath()
	}
	path = ExpandHome(path)

	data := defaultData
	if _, err := os.Stat(path); err == nil {
		d, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		data = d
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	cfg.expand()
	return &cfg, nil
}

func (c *Config) expand() {
	c.Vault.MountPoint = ExpandHome(c.Vault.MountPoint)
	c.Guard.WatchPaths = expandSlice(c.Guard.WatchPaths)
	for i := range c.Guard.Zones {
		c.Guard.Zones[i].Path = ExpandHome(c.Guard.Zones[i].Path)
	}
	for i := range c.Guard.PathRules {
		c.Guard.PathRules[i].Path = ExpandHome(c.Guard.PathRules[i].Path)
	}
	c.Shell.AgentHome = ExpandHome(c.Shell.AgentHome)
	c.Audit.DBPath = ExpandHome(c.Audit.DBPath)
}

// ExpandHome replaces a leading ~ with the current user's home directory.
func ExpandHome(path string) string {
	if path == "" {
		return path
	}
	if path == "~" {
		home, _ := os.UserHomeDir()
		return home
	}
	if strings.HasPrefix(path, "~/") {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, path[2:])
	}
	return path
}

func expandSlice(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = ExpandHome(s)
	}
	return out
}
