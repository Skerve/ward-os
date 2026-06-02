// ward-shell is a hardened shell wrapper intended to be used as the shell for
// AI agents and CLI tools. It:
//
//  1. Strips secrets from the environment (AWS keys, tokens, SSH agent, etc.)
//  2. Redirects $HOME to a sandbox directory so the agent cannot navigate to
//     the real home directory by default.
//  3. Logs every command executed (via shell history trick) to the audit log.
//  4. Exec's into the real shell so the agent still gets a normal shell experience.
//
// Usage:
//
//	ward-shell [flags] [-- shell-args...]
//
// Configure agents to use ward-shell as their shell, e.g. in Cursor settings:
//
//	"terminal.integrated.shell.osx": "/usr/local/bin/ward-shell"
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/skerve/ward-os/internal/config"
	"github.com/skerve/ward-os/internal/version"
)

var (
	cfgPath   string
	realShell string
	noSandbox bool
)

func main() {
	root := &cobra.Command{
		Use:     "ward-shell [-- shell-args...]",
		Short:   "Hardened shell wrapper — strips secrets, sandboxes home, logs commands",
		Version: version.String(),
		RunE:    run,
	}

	root.Flags().StringVar(&cfgPath, "config", "", "config file (default: ~/.config/ward-os/ward.yaml)")
	root.Flags().StringVar(&realShell, "shell", "", "real shell to exec (default: $SHELL or /bin/zsh)")
	root.Flags().BoolVar(&noSandbox, "no-sandbox", false, "skip home redirection (still strips env)")

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		// Non-fatal: run with built-in defaults.
		fmt.Fprintf(os.Stderr, "ward-shell: config load warning: %v\n", err)
		cfg = defaultConfig()
	}

	shell := realShell
	if shell == "" {
		shell = os.Getenv("SHELL")
	}
	if shell == "" {
		shell = "/bin/zsh"
	}

	// Build sanitised environment.
	env := sanitiseEnv(os.Environ(), cfg.Shell)

	// Set up sandbox home if configured.
	if !noSandbox && cfg.Shell.AgentHome != "" {
		sandboxHome := config.ExpandHome(cfg.Shell.AgentHome)
		if err := os.MkdirAll(sandboxHome, 0o700); err != nil {
			fmt.Fprintf(os.Stderr, "ward-shell: cannot create sandbox home %s: %v\n", sandboxHome, err)
		} else {
			env = setEnv(env, "HOME", sandboxHome)
			env = setEnv(env, "XDG_DATA_HOME", filepath.Join(sandboxHome, ".local", "share"))
			env = setEnv(env, "XDG_CONFIG_HOME", filepath.Join(sandboxHome, ".config"))
			env = setEnv(env, "XDG_CACHE_HOME", filepath.Join(sandboxHome, ".cache"))
		}
	}

	// Inject HISTFILE into sandbox so shell history goes to a separate file.
	if !noSandbox && cfg.Shell.AgentHome != "" {
		histFile := filepath.Join(config.ExpandHome(cfg.Shell.AgentHome), ".ward_shell_history")
		env = setEnv(env, "HISTFILE", histFile)
	}

	// Inject a PROMPT_COMMAND / precmd that writes each command to the audit log.
	if cfg.Shell.LogCommands {
		logScript := buildLogScript(*cfg)
		switch filepath.Base(shell) {
		case "zsh":
			existing := getEnv(env, "ZDOTDIR")
			if existing == "" {
				existing = os.Getenv("ZDOTDIR")
			}
			zdotdir := setupZdotdir(existing, logScript, cfg.Shell.AgentHome)
			if zdotdir != "" {
				env = setEnv(env, "ZDOTDIR", zdotdir)
			}
		case "bash":
			env = setEnv(env, "PROMPT_COMMAND", logScript+"; "+getEnv(env, "PROMPT_COMMAND"))
		}
	}

	fmt.Fprintf(os.Stderr, "ward-shell: launching %s (env sanitised, %d vars stripped)\n",
		shell, countStripped(os.Environ(), cfg.Shell))

	shellPath, err := exec.LookPath(shell)
	if err != nil {
		shellPath = shell
	}

	shellArgs := []string{shellPath}
	shellArgs = append(shellArgs, args...)

	return syscall.Exec(shellPath, shellArgs, env)
}

// sanitiseEnv strips dangerous environment variables.
func sanitiseEnv(env []string, cfg config.ShellConfig) []string {
	var out []string
	for _, kv := range env {
		key := envKey(kv)
		if shouldStrip(key, cfg) {
			continue
		}
		out = append(out, kv)
	}
	return out
}

func shouldStrip(key string, cfg config.ShellConfig) bool {
	upper := strings.ToUpper(key)
	for _, prefix := range cfg.StripEnvPrefixes {
		if strings.HasPrefix(upper, strings.ToUpper(prefix)) {
			return true
		}
	}
	for _, name := range cfg.StripEnvVars {
		if strings.EqualFold(key, name) {
			return true
		}
	}
	return false
}

func countStripped(env []string, cfg config.ShellConfig) int {
	n := 0
	for _, kv := range env {
		if shouldStrip(envKey(kv), cfg) {
			n++
		}
	}
	return n
}

func envKey(kv string) string {
	if i := strings.IndexByte(kv, '='); i >= 0 {
		return kv[:i]
	}
	return kv
}

func getEnv(env []string, key string) string {
	prefix := key + "="
	for _, kv := range env {
		if strings.HasPrefix(kv, prefix) {
			return kv[len(prefix):]
		}
	}
	return ""
}

func setEnv(env []string, key, val string) []string {
	prefix := key + "="
	for i, kv := range env {
		if strings.HasPrefix(kv, prefix) {
			env[i] = key + "=" + val
			return env
		}
	}
	return append(env, key+"="+val)
}

// buildLogScript returns a shell one-liner that appends the current command
// to the ward audit log file.
func buildLogScript(cfg config.Config) string {
	logFile := filepath.Join(filepath.Dir(config.ExpandHome(cfg.Audit.DBPath)), "shell-commands.log")
	return fmt.Sprintf(
		`echo "$(date -u +%%Y-%%m-%%dT%%H:%%M:%%SZ) PID=$$ CMD=$(history 1 | sed 's/^ *[0-9]* *//')" >> %s`,
		logFile,
	)
}

// setupZdotdir creates a temporary ZDOTDIR with a .zshrc that sources the
// original and adds our precmd hook.
func setupZdotdir(originalZdotdir, logScript, agentHome string) string {
	base := config.ExpandHome(agentHome)
	if base == "" {
		var err error
		base, err = os.MkdirTemp("", "ward-shell-*")
		if err != nil {
			return ""
		}
	}

	zdotdir := filepath.Join(base, ".ward-zdotdir-"+fmt.Sprintf("%d", time.Now().Unix()))
	if err := os.MkdirAll(zdotdir, 0o700); err != nil {
		return ""
	}

	// Write a .zshrc that sources the original and adds our precmd.
	var origRC string
	if originalZdotdir != "" {
		origRC = fmt.Sprintf(`[ -f %s/.zshrc ] && source %s/.zshrc`, originalZdotdir, originalZdotdir)
	} else {
		origRC = `[ -f ~/.zshrc ] && source ~/.zshrc`
	}

	content := fmt.Sprintf(`%s

# ward-shell: log commands
autoload -Uz add-zsh-hook
_ward_precmd() {
  local cmd
  cmd=$(fc -ln -1 2>/dev/null)
  if [ -n "$cmd" ]; then
    echo "$(date -u +%%Y-%%m-%%dT%%H:%%M:%%SZ) PID=$$ CMD=$cmd" >> %s
  fi
}
add-zsh-hook precmd _ward_precmd
`, origRC, logScript)

	rcPath := filepath.Join(zdotdir, ".zshrc")
	if err := os.WriteFile(rcPath, []byte(content), 0o600); err != nil {
		return ""
	}
	return zdotdir
}

func loadConfig() (*config.Config, error) {
	defaultData, _ := os.ReadFile(filepath.Join(
		filepath.Dir(os.Args[0]), "..", "config", "ward.yaml",
	))
	return config.LoadOrDefault(cfgPath, defaultData)
}

func defaultConfig() *config.Config {
	return &config.Config{
		Shell: config.ShellConfig{
			StripEnvPrefixes: []string{"AWS_", "GITHUB_", "GH_", "GITLAB_", "OPENAI_", "ANTHROPIC_"},
			StripEnvVars:     []string{"SSH_AUTH_SOCK", "SSH_AGENT_PID", "VAULT_TOKEN"},
			LogCommands:      true,
		},
		Audit: config.AuditConfig{
			DBPath: "~/.local/share/ward-os/audit.db",
		},
	}
}
