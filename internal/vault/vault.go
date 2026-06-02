// Package vault manages an encrypted APFS sparsebundle that is mounted
// directly at ~/.ward (or another configured path).
//
// Design principles:
//   - The vault is a personal safe-deposit box for USER secrets only.
//   - System config paths (.ssh, .aws, .gnupg, …) are NEVER moved or touched.
//     Those stay in their original locations and always work normally.
//   - When the vault is unmounted, only ~/.ward is inaccessible.
//     All other tools (ssh, git, brew, aws, npm, …) continue to function.
package vault

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/skerve/ward-os/internal/config"
)

// Vault wraps a macOS encrypted APFS sparsebundle.
type Vault struct {
	cfg  config.VaultConfig
	home string
}

// New creates a Vault handle from the given config.
func New(cfg config.VaultConfig) (*Vault, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	return &Vault{cfg: cfg, home: home}, nil
}

// BundlePath returns the on-disk path of the sparsebundle file.
// Stored next to the home directory, not inside it, to keep ~ tidy.
func (v *Vault) BundlePath() string {
	return filepath.Join(v.home, v.cfg.Name+".sparsebundle")
}

// MountPoint returns the directory where the vault will be mounted.
// This is ~/.ward by default.
func (v *Vault) MountPoint() string {
	return config.ExpandHome(v.cfg.MountPoint)
}

// Exists reports whether the sparsebundle has been created.
func (v *Vault) Exists() bool {
	_, err := os.Stat(v.BundlePath())
	return err == nil
}

// IsMounted reports whether the vault volume is currently mounted.
func (v *Vault) IsMounted() bool {
	// The mount point exists AND has content (is not an empty placeholder dir).
	entries, err := os.ReadDir(v.MountPoint())
	return err == nil && len(entries) > 0
}

// Create creates a new AES-256 encrypted APFS sparsebundle and mounts it
// at MountPoint(). It creates subdirectories for common secret categories.
func (v *Vault) Create() error {
	if v.Exists() {
		return fmt.Errorf("vault already exists at %s", v.BundlePath())
	}

	mountPoint := v.MountPoint()
	fmt.Printf("Creating encrypted vault:\n")
	fmt.Printf("  Bundle : %s\n", v.BundlePath())
	fmt.Printf("  Mount  : %s\n", mountPoint)
	fmt.Printf("  Size   : %s\n", v.cfg.Size)
	fmt.Println()
	fmt.Println("macOS will prompt for a passphrase (or Touch ID) to protect the vault.")
	fmt.Println()

	if err := os.MkdirAll(mountPoint, 0o700); err != nil {
		return fmt.Errorf("creating mount point %s: %w", mountPoint, err)
	}

	args := []string{
		"create",
		"-size", v.cfg.Size,
		"-fs", "APFS",
		"-volname", v.cfg.VolumeLabel,
		"-encryption", "AES-256",
		"-type", "SPARSEBUNDLE",
		"-agentpass",
		v.BundlePath(),
	}

	cmd := exec.CommandContext(context.Background(), "hdiutil", args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("hdiutil create: %w", err)
	}

	if err := v.mount(); err != nil {
		return fmt.Errorf("initial mount after create: %w", err)
	}

	// Create a sensible directory structure inside the vault.
	for _, dir := range []string{"keys", "tokens", "certs", "notes", "env"} {
		p := filepath.Join(mountPoint, dir)
		if err := os.MkdirAll(p, 0o700); err != nil {
			return fmt.Errorf("creating vault dir %s: %w", dir, err)
		}
	}

	// Write a README inside the vault so its purpose is clear.
	readme := `# ~/.ward — ward-os encrypted secrets vault

This directory is an AES-256 encrypted APFS volume.
It is only accessible when the vault is mounted with: ward vault mount

Suggested layout:
  keys/      — API keys, PATs, service account credentials
  tokens/    — OAuth tokens, session tokens
  certs/     — TLS certificates, private keys (do NOT put ~/.ssh keys here)
  env/       — .env files for local projects
  notes/     — sensitive notes, seed phrases, etc.

Manage secrets with:
  ward secret set  <name> <value>   (stored under keys/)
  ward secret get  <name>
  ward secret list
  ward secret delete <name>

Note: ~/.ssh, ~/.aws, ~/.gnupg and other system config dirs are NOT stored here.
They remain in their original locations so that ssh, git, brew, etc. always work.
`
	_ = os.WriteFile(filepath.Join(mountPoint, "README.md"), []byte(readme), 0o600)

	fmt.Printf("\nVault created and mounted at %s\n", mountPoint)
	fmt.Println("Subdirectories created: keys/, tokens/, certs/, env/, notes/")
	fmt.Println()
	fmt.Println("Your ~/.ssh, ~/.aws, and other system paths are unchanged.")
	fmt.Println("Normal tools (ssh, git, brew, aws, npm, …) continue to work as before.")
	fmt.Println()
	fmt.Println("Run `ward vault unmount` to lock the vault when not needed.")
	return nil
}

// Mount mounts the sparsebundle at MountPoint(), prompting for credentials.
func (v *Vault) Mount() error {
	if !v.Exists() {
		return fmt.Errorf("vault not found at %s\nRun `ward vault create` first", v.BundlePath())
	}
	if v.IsMounted() {
		fmt.Printf("Vault is already mounted at %s\n", v.MountPoint())
		return nil
	}
	if err := v.mount(); err != nil {
		return err
	}
	fmt.Printf("Vault mounted at %s\n", v.MountPoint())
	return nil
}

func (v *Vault) mount() error {
	// Mount to a /Volumes/<label> first, then bind the mount point dir.
	// Simpler approach: use -mountpoint to mount directly at MountPoint().
	cmd := exec.CommandContext(context.Background(), "hdiutil", "attach",
		"-agentpass",
		"-mountpoint", v.MountPoint(),
		v.BundlePath(),
	)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("hdiutil attach: %w", err)
	}
	time.Sleep(300 * time.Millisecond)
	return nil
}

// Unmount ejects the vault volume.
func (v *Vault) Unmount() error {
	if !v.Exists() {
		return fmt.Errorf("no vault found at %s", v.BundlePath())
	}
	if !v.IsMounted() {
		fmt.Println("Vault is already unmounted (locked).")
		return nil
	}
	cmd := exec.CommandContext(context.Background(), "hdiutil", "detach", v.MountPoint())
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("hdiutil detach: %w", err)
	}
	fmt.Printf("Vault locked. %s is now inaccessible.\n", v.MountPoint())
	fmt.Println("All other tools (ssh, git, brew, aws, …) are unaffected.")
	return nil
}

// Status prints vault information.
func (v *Vault) Status() {
	fmt.Printf("Bundle    : %s\n", v.BundlePath())
	fmt.Printf("MountPoint: %s\n", v.MountPoint())

	if !v.Exists() {
		fmt.Println("Status    : NOT CREATED — run `ward vault create`")
		return
	}

	if v.IsMounted() {
		entries, _ := os.ReadDir(v.MountPoint())
		fmt.Printf("Status    : MOUNTED (%d item(s) visible)\n", len(entries))
	} else {
		fmt.Println("Status    : unmounted (locked)")
	}
}

// Destroy unmounts and deletes the sparsebundle. All data inside is lost.
func (v *Vault) Destroy() error {
	if !v.Exists() {
		return fmt.Errorf("no vault found")
	}
	if v.IsMounted() {
		if err := v.Unmount(); err != nil {
			return err
		}
	}
	fmt.Printf("Deleting %s...\n", v.BundlePath())
	if err := os.RemoveAll(v.BundlePath()); err != nil {
		return err
	}
	fmt.Println("Vault destroyed.")
	return nil
}

// SecretsDir returns the path to the keys/ subdirectory inside the vault.
func (v *Vault) SecretsDir() string {
	return filepath.Join(v.MountPoint(), "keys")
}
