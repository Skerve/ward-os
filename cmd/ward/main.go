package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/skerve/ward-os/internal/allow"
	"github.com/skerve/ward-os/internal/audit"
	"github.com/skerve/ward-os/internal/config"
	"github.com/skerve/ward-os/internal/vault"
	"github.com/skerve/ward-os/internal/version"
)

var cfgPath string

func main() {
	root := &cobra.Command{
		Use:     "ward",
		Short:   "ward-os — home directory guardian",
		Version: version.String(),
		Long: `ward-os protects your home directory from AI agents and CLI tools.

Commands:
  ward status          — overall protection status
  ward vault ...       — manage the encrypted secrets vault
  ward logs            — show recent access violations
  ward ignore install  — write ~/.cursorignore
  ward version         — print version information`,
	}

	root.PersistentFlags().StringVar(&cfgPath, "config", "", "config file (default: ~/.config/ward-os/ward.yaml)")

	root.AddCommand(
		statusCmd(),
		vaultCmd(),
		logsCmd(),
		ignoreCmd(),
		shellInitCmd(),
		secretCmd(),
		allowCmd(),
		versionCmd(),
	)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show overall protection status",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}

			fmt.Println("═══════════════════════════════════════")
			fmt.Println("  ward-os  — protection status")
			fmt.Println("═══════════════════════════════════════")
			fmt.Println()

			// Vault status
			fmt.Println("── Vault (~/.ward) ────────────────────")
			v, _ := vault.New(cfg.Vault)
			v.Status()
			fmt.Println()
			fmt.Println("  Note: ~/.ssh, ~/.aws, ~/.gnupg etc. are NOT in the vault.")
			fmt.Println("  They are always accessible. Normal tools are unaffected.")
			fmt.Println()

			// Guard daemon
			fmt.Println("── Guard daemon ───────────────────────")
			if guardRunning() {
				fmt.Println("  ward-guard: RUNNING")
			} else {
				fmt.Println("  ward-guard: NOT RUNNING  (run: ward-guard &)")
			}
			fmt.Println()

			// Cursor ignore
			fmt.Println("── .cursorignore ──────────────────────")
			home, _ := os.UserHomeDir()
			ci := filepath.Join(home, ".cursorignore")
			if _, err := os.Stat(ci); err == nil {
				fmt.Printf("  %s: present\n", ci)
			} else {
				fmt.Printf("  %s: MISSING  (run: ward ignore install)\n", ci)
			}
			fmt.Println()

			// Recent violations
			fmt.Println("── Recent violations ──────────────────")
			dbPath := config.ExpandHome(cfg.Audit.DBPath)
			a, err := audit.Open(dbPath)
			if err != nil {
				fmt.Println("  (audit db not yet created)")
			} else {
				defer a.Close()
				entries, _ := a.Recent(5)
				if len(entries) == 0 {
					fmt.Println("  No violations recorded.")
				} else {
					for _, e := range entries {
						fmt.Printf("  %s  %-20s  %s  [%s]\n",
							e.Time.Local().Format("2006-01-02 15:04:05"),
							e.ProcessName,
							e.Path,
							e.Action,
						)
					}
				}
			}
			return nil
		},
	}
}

// guardRunning checks whether ward-guard is running by looking for its process.
func guardRunning() bool {
	// Use pgrep for simplicity.
	out, err := runOutput("pgrep", "-x", "ward-guard")
	return err == nil && len(out) > 0
}

// ---------------------------------------------------------------------------
// vault
// ---------------------------------------------------------------------------

func vaultCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vault",
		Short: "Manage the encrypted secrets vault",
	}

	cmd.AddCommand(
		&cobra.Command{
			Use:   "create",
			Short: "Create and populate the encrypted vault (interactive)",
			RunE: func(cmd *cobra.Command, args []string) error {
				cfg, err := loadConfig()
				if err != nil {
					return err
				}
				v, err := vault.New(cfg.Vault)
				if err != nil {
					return err
				}
				return v.Create()
			},
		},
		&cobra.Command{
			Use:   "mount",
			Short: "Mount (unlock) the vault — prompts for credentials",
			RunE: func(cmd *cobra.Command, args []string) error {
				cfg, err := loadConfig()
				if err != nil {
					return err
				}
				v, err := vault.New(cfg.Vault)
				if err != nil {
					return err
				}
				return v.Mount()
			},
		},
		&cobra.Command{
			Use:   "unmount",
			Short: "Unmount (lock) the vault",
			RunE: func(cmd *cobra.Command, args []string) error {
				cfg, err := loadConfig()
				if err != nil {
					return err
				}
				v, err := vault.New(cfg.Vault)
				if err != nil {
					return err
				}
				return v.Unmount()
			},
		},
		&cobra.Command{
			Use:   "status",
			Short: "Show vault status and protected paths",
			RunE: func(cmd *cobra.Command, args []string) error {
				cfg, err := loadConfig()
				if err != nil {
					return err
				}
				v, err := vault.New(cfg.Vault)
				if err != nil {
					return err
				}
				v.Status()
				return nil
			},
		},
		&cobra.Command{
			Use:   "destroy",
			Short: "Restore data from vault and delete the bundle (IRREVERSIBLE)",
			RunE: func(cmd *cobra.Command, args []string) error {
				cfg, err := loadConfig()
				if err != nil {
					return err
				}
				v, err := vault.New(cfg.Vault)
				if err != nil {
					return err
				}
				fmt.Print("This will restore all data from the vault and DELETE the encrypted bundle.\nType 'yes' to confirm: ")
				var confirm string
				fmt.Scanln(&confirm)
				if confirm != "yes" {
					fmt.Println("Aborted.")
					return nil
				}
				return v.Destroy()
			},
		},
	)

	return cmd
}

// ---------------------------------------------------------------------------
// logs
// ---------------------------------------------------------------------------

func logsCmd() *cobra.Command {
	var (
		n    int
		since string
	)

	cmd := &cobra.Command{
		Use:   "logs",
		Short: "Show audit log of access violations",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			dbPath := config.ExpandHome(cfg.Audit.DBPath)
			a, err := audit.Open(dbPath)
			if err != nil {
				return fmt.Errorf("opening audit db: %w", err)
			}
			defer a.Close()

			var entries []audit.Entry
			if since != "" {
				t, err := time.Parse("2006-01-02", since)
				if err != nil {
					return fmt.Errorf("invalid date %q (use YYYY-MM-DD): %w", since, err)
				}
				entries, err = a.Since(t)
				if err != nil {
					return err
				}
			} else {
				entries, err = a.Recent(n)
				if err != nil {
					return err
				}
			}

			if len(entries) == 0 {
				fmt.Println("No violations recorded.")
				return nil
			}

			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "TIME\tPROCESS\tPID\tOP\tACTION\tPATH")
			for _, e := range entries {
				fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\t%s\n",
					e.Time.Local().Format("2006-01-02 15:04:05"),
					e.ProcessName,
					e.PID,
					e.Operation,
					e.Action,
					e.Path,
				)
			}
			return tw.Flush()
		},
	}

	cmd.Flags().IntVarP(&n, "lines", "n", 50, "number of recent entries to show")
	cmd.Flags().StringVar(&since, "since", "", "show entries since date (YYYY-MM-DD)")
	return cmd
}

// ---------------------------------------------------------------------------
// ignore
// ---------------------------------------------------------------------------

func ignoreCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ignore",
		Short: "Manage agent ignore files",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "install",
		Short: "Write ~/.cursorignore with sensitive path patterns",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}

			home, _ := os.UserHomeDir()
			ciPath := filepath.Join(home, ".cursorignore")

			// Merge with existing entries if file already exists.
			existing := map[string]bool{}
			if data, err := os.ReadFile(ciPath); err == nil {
				for _, line := range splitLines(string(data)) {
					if line != "" {
						existing[line] = true
					}
				}
			}

			var toAdd []string
			for _, entry := range cfg.Ignore.CursorEntries {
				if !existing[entry] {
					toAdd = append(toAdd, entry)
					existing[entry] = true
				}
			}

			if len(toAdd) == 0 {
				fmt.Println("~/.cursorignore already up to date.")
				return nil
			}

			f, err := os.OpenFile(ciPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
			if err != nil {
				return fmt.Errorf("opening %s: %w", ciPath, err)
			}
			defer f.Close()

			header := "\n# ward-os — auto-generated sensitive paths\n"
			if _, err := fmt.Fprint(f, header); err != nil {
				return err
			}
			for _, entry := range toAdd {
				if _, err := fmt.Fprintln(f, entry); err != nil {
					return err
				}
			}

			fmt.Printf("Added %d entries to %s\n", len(toAdd), ciPath)
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "show",
		Short: "Print what would be written to ~/.cursorignore",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			for _, entry := range cfg.Ignore.CursorEntries {
				fmt.Println(entry)
			}
			return nil
		},
	})

	return cmd
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func loadConfig() (*config.Config, error) {
	defaultData, _ := os.ReadFile(filepath.Join(
		filepath.Dir(os.Args[0]), "..", "config", "ward.yaml",
	))
	return config.LoadOrDefault(cfgPath, defaultData)
}

func runOutput(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).Output()
}

// ---------------------------------------------------------------------------
// version
// ---------------------------------------------------------------------------

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("ward %s\n", version.String())
		},
	}
}

// ---------------------------------------------------------------------------
// allow
// ---------------------------------------------------------------------------

func allowCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "allow",
		Short: "Manage access grants for protected zones (tier-2 paths)",
		Long: `Grant temporary or permanent access to protected zones for specific paths or processes.

Tier-2 zones (Documents, Desktop, dotfolders, etc.) kill unauthorised processes by default.
Use 'ward allow add' to create an exception before running an agent on a protected area.

Examples:
  ward allow add ~/Documents/my-project               # permanent grant for that subfolder
  ward allow add ~/Desktop --duration 1h              # grant expires in 1 hour
  ward allow add ~/Documents --process cursor-agent   # grant only for cursor-agent
  ward allow list                                     # show active grants
  ward allow revoke 3                                 # revoke grant #3`,
	}

	// add
	var (
		duration string
		process  string
		note     string
	)
	addCmd := &cobra.Command{
		Use:   "add <path>",
		Short: "Grant access to a protected path",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := openAllowStore()
			if err != nil {
				return err
			}
			defer store.Close()

			var d time.Duration
			if duration != "" {
				d, err = time.ParseDuration(duration)
				if err != nil {
					return fmt.Errorf("invalid duration %q (examples: 30m, 2h, 24h): %w", duration, err)
				}
			}

			path := config.ExpandHome(args[0])
			g, err := store.Add(path, process, note, d)
			if err != nil {
				return fmt.Errorf("adding grant: %w", err)
			}

			fmt.Printf("Grant #%d created:\n", g.ID)
			fmt.Printf("  Path    : %s\n", g.Path)
			if g.Process != "" {
				fmt.Printf("  Process : %s\n", g.Process)
			} else {
				fmt.Printf("  Process : any\n")
			}
			if g.ExpiresAt.IsZero() {
				fmt.Printf("  Expires : never (permanent)\n")
			} else {
				fmt.Printf("  Expires : %s (%s from now)\n",
					g.ExpiresAt.Local().Format("2006-01-02 15:04:05"),
					time.Until(g.ExpiresAt).Round(time.Minute),
				)
			}
			return nil
		},
	}
	addCmd.Flags().StringVarP(&duration, "duration", "d", "", "how long the grant is valid (e.g. 30m, 2h, 24h); omit for permanent")
	addCmd.Flags().StringVarP(&process, "process", "p", "", "restrict to a specific process name (e.g. cursor-agent)")
	addCmd.Flags().StringVarP(&note, "note", "n", "", "optional note describing why this grant exists")

	// list
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "Show all active access grants",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := openAllowStore()
			if err != nil {
				return err
			}
			defer store.Close()

			grants, err := store.List()
			if err != nil {
				return err
			}

			if len(grants) == 0 {
				fmt.Println("No active grants.")
				fmt.Println("(Tier-2 zones will kill any unauthorised process that touches them.)")
				return nil
			}

			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tPATH\tPROCESS\tEXPIRES\tNOTE")
			for _, g := range grants {
				exp := "never"
				if !g.ExpiresAt.IsZero() {
					remaining := time.Until(g.ExpiresAt).Round(time.Minute)
					exp = g.ExpiresAt.Local().Format("15:04") + " (in " + remaining.String() + ")"
				}
				proc := g.Process
				if proc == "" {
					proc = "any"
				}
				fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\n",
					g.ID, g.Path, proc, exp, g.Note)
			}
			return tw.Flush()
		},
	}

	// revoke
	revokeCmd := &cobra.Command{
		Use:   "revoke <id>",
		Short: "Revoke an access grant by ID",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := openAllowStore()
			if err != nil {
				return err
			}
			defer store.Close()

			id, err := parseInt64(args[0])
			if err != nil {
				return fmt.Errorf("invalid id %q: %w", args[0], err)
			}
			if err := store.Revoke(id); err != nil {
				return err
			}
			fmt.Printf("Grant #%d revoked.\n", id)
			return nil
		},
	}

	cmd.AddCommand(addCmd, listCmd, revokeCmd)
	return cmd
}

func openAllowStore() (*allow.Store, error) {
	cfg, err := loadConfig()
	if err != nil {
		return nil, err
	}
	return allow.Open(config.ExpandHome(cfg.Audit.DBPath))
}

func parseInt64(s string) (int64, error) {
	var n int64
	_, err := fmt.Sscanf(s, "%d", &n)
	return n, err
}

// ---------------------------------------------------------------------------
// secret
// ---------------------------------------------------------------------------

// secretCmd manages named secrets stored inside the vault's keys/ directory.
// Each secret is a plain text file: ~/.ward/keys/<name>
// The file is readable only by the owner (0600) and only accessible when
// the vault is mounted.
func secretCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "secret",
		Short: "Manage secrets stored inside the vault (~/.ward/keys/)",
		Long: `Store and retrieve named secrets inside the encrypted vault.

Each secret is a file at ~/.ward/keys/<name>.
The vault must be mounted (ward vault mount) to use these commands.`,
	}

	// set
	setCmd := &cobra.Command{
		Use:   "set <name> [value]",
		Short: "Store a secret (reads from stdin if value is omitted)",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, err := secretsDir()
			if err != nil {
				return err
			}
			name := sanitiseName(args[0])
			var value []byte
			if len(args) == 2 {
				value = []byte(args[1])
			} else {
				fmt.Fprintf(os.Stderr, "Enter value for %q (Ctrl-D to finish): ", name)
				buf := make([]byte, 0, 256)
				chunk := make([]byte, 256)
				for {
					n, err2 := os.Stdin.Read(chunk)
					buf = append(buf, chunk[:n]...)
					if err2 != nil {
						break
					}
				}
				value = buf
			}
			path := filepath.Join(dir, name)
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				return err
			}
			if err := os.WriteFile(path, value, 0o600); err != nil {
				return fmt.Errorf("writing secret: %w", err)
			}
			fmt.Printf("Secret %q stored.\n", name)
			return nil
		},
	}

	// get
	getCmd := &cobra.Command{
		Use:   "get <name>",
		Short: "Print a secret value to stdout",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, err := secretsDir()
			if err != nil {
				return err
			}
			name := sanitiseName(args[0])
			data, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				if os.IsNotExist(err) {
					return fmt.Errorf("secret %q not found", name)
				}
				return err
			}
			fmt.Print(string(data))
			return nil
		},
	}

	// list
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List all stored secret names",
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, err := secretsDir()
			if err != nil {
				return err
			}
			return listSecrets(dir, "")
		},
	}

	// delete
	deleteCmd := &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete a secret",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, err := secretsDir()
			if err != nil {
				return err
			}
			name := sanitiseName(args[0])
			path := filepath.Join(dir, name)
			if err := os.Remove(path); err != nil {
				if os.IsNotExist(err) {
					return fmt.Errorf("secret %q not found", name)
				}
				return err
			}
			fmt.Printf("Secret %q deleted.\n", name)
			return nil
		},
	}

	cmd.AddCommand(setCmd, getCmd, listCmd, deleteCmd)
	return cmd
}

// secretsDir returns the keys/ directory inside the vault, checking that it
// is accessible (i.e. the vault is mounted).
func secretsDir() (string, error) {
	cfg, err := loadConfig()
	if err != nil {
		return "", err
	}
	v, err := vault.New(cfg.Vault)
	if err != nil {
		return "", err
	}
	if !v.IsMounted() {
		return "", fmt.Errorf("vault is not mounted — run `ward vault mount` first")
	}
	dir := v.SecretsDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("creating secrets dir: %w", err)
	}
	return dir, nil
}

// sanitiseName prevents path traversal in secret names.
func sanitiseName(name string) string {
	// Allow slashes so users can namespace: "aws/prod", "gh/token"
	// but block traversal sequences.
	clean := filepath.Clean(name)
	if strings.HasPrefix(clean, "..") || strings.HasPrefix(clean, "/") {
		return filepath.Base(clean)
	}
	return clean
}

// listSecrets prints all secret names under dir, recursively.
func listSecrets(dir, prefix string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("reading secrets dir: %w", err)
	}
	if len(entries) == 0 {
		fmt.Println("(no secrets stored)")
		return nil
	}
	for _, e := range entries {
		name := e.Name()
		if prefix != "" {
			name = prefix + "/" + name
		}
		if e.IsDir() {
			if err := listSecrets(filepath.Join(dir, e.Name()), name); err != nil {
				return err
			}
		} else {
			info, _ := e.Info()
			size := int64(0)
			if info != nil {
				size = info.Size()
			}
			fmt.Printf("  %-40s  %d bytes\n", name, size)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// shell-init
// ---------------------------------------------------------------------------

// shellInitCmd returns a command that either prints the shell snippet or
// installs it directly into ~/.zshrc / ~/.bashrc.
func shellInitCmd() *cobra.Command {
	var install bool

	cmd := &cobra.Command{
		Use:   "shell-init",
		Short: "Print (or install) the shell hook that auto-checks vault status on login",
		Long: `Prints a shell snippet that:
  • Checks whether the vault is mounted each time you open a terminal.
  • Prompts you to mount it if it is locked (so you never work with broken symlinks).
  • Warns if ward-guard is not running.

Run with --install to append it automatically to ~/.zshrc (zsh) or ~/.bashrc (bash).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			snippet := shellInitSnippet()
			if !install {
				fmt.Print(snippet)
				fmt.Println("\n# Add this to your shell rc file, or run: ward shell-init --install")
				return nil
			}
			return installShellInit(snippet)
		},
	}

	cmd.Flags().BoolVar(&install, "install", false, "append the snippet to ~/.zshrc (zsh) or ~/.bashrc (bash)")
	return cmd
}

const shellInitMarkerStart = "# >>> ward-os shell-init start <<<"
const shellInitMarkerEnd   = "# >>> ward-os shell-init end <<<"

func shellInitSnippet() string {
	return shellInitMarkerStart + `
# Auto-check ward-os vault status on every new terminal session.
# Generated by: ward shell-init
_ward_check() {
  # Skip inside ward-shell itself (already sandboxed).
  [ "${WARD_SHELL:-}" = "1" ] && return

  local ward_bin
  ward_bin="$(command -v ward 2>/dev/null)" || return

  # Check if the guard daemon is running.
  if ! pgrep -qx ward-guard 2>/dev/null; then
    echo "ward-os: ward-guard is NOT running. Start it with: ward-guard &" >&2
  fi

  # Check vault status by testing whether the first protected symlink resolves.
  local vault_vol
  vault_vol="$("$ward_bin" vault status 2>/dev/null | grep 'Status.*MOUNTED')"
  if [ -z "$vault_vol" ]; then
    echo ""
    echo "  ward-os: vault is LOCKED — sensitive paths (~/.ssh, ~/.aws, etc.) are inaccessible."
    echo "  Run 'ward vault mount' to unlock before using git, aws, ssh, etc."
    echo ""
  fi
}
_ward_check
` + shellInitMarkerEnd + "\n"
}

func installShellInit(snippet string) error {
	home, _ := os.UserHomeDir()
	shell := os.Getenv("SHELL")

	rcFile := filepath.Join(home, ".zshrc")
	if filepath.Base(shell) == "bash" {
		rcFile = filepath.Join(home, ".bashrc")
	}

	// Read existing content.
	existing := ""
	if data, err := os.ReadFile(rcFile); err == nil {
		existing = string(data)
	}

	// Remove any previous installation so we don't duplicate.
	existing = removeBlock(existing, shellInitMarkerStart, shellInitMarkerEnd)

	// Append fresh snippet.
	content := strings.TrimRight(existing, "\n") + "\n\n" + snippet
	if err := os.WriteFile(rcFile, []byte(content), 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", rcFile, err)
	}

	fmt.Printf("Installed shell hook into %s\n", rcFile)
	fmt.Println("Open a new terminal (or run `source " + rcFile + "`) to activate.")
	return nil
}

// removeBlock removes everything between startMarker and endMarker (inclusive).
func removeBlock(s, startMarker, endMarker string) string {
	start := strings.Index(s, startMarker)
	if start == -1 {
		return s
	}
	end := strings.Index(s, endMarker)
	if end == -1 {
		return s[:start]
	}
	end += len(endMarker)
	// Eat the trailing newline if present.
	if end < len(s) && s[end] == '\n' {
		end++
	}
	return s[:start] + s[end:]
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}
