<div align="center">

# ward-os

**Home directory guardian — protects your machine against AI agent and CLI tool access to your files.**

[![CI](https://github.com/skerve/ward-os/actions/workflows/ci.yml/badge.svg)](https://github.com/skerve/ward-os/actions/workflows/ci.yml)
[![Lint](https://github.com/skerve/ward-os/actions/workflows/lint.yml/badge.svg)](https://github.com/skerve/ward-os/actions/workflows/lint.yml)
[![Latest Release](https://img.shields.io/github/v/release/skerve/ward-os?sort=semver)](https://github.com/skerve/ward-os/releases/latest)
[![Go Version](https://img.shields.io/github/go-mod/go-version/skerve/ward-os)](go.mod)
[![Go Report Card](https://goreportcard.com/badge/github.com/skerve/ward-os)](https://goreportcard.com/report/github.com/skerve/ward-os)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform: macOS](https://img.shields.io/badge/platform-macOS-lightgrey?logo=apple)](https://github.com/skerve/ward-os/releases)

</div>

---

## Design principle

> Normal processes must always work. Only agents are constrained — unless you explicitly say otherwise.

`~/.ssh`, `~/.aws`, `~/.gnupg`, and other system config paths are **never moved or touched**. `ssh`, `git`, `brew`, `aws`, `npm`, and every other normal tool continue to work exactly as before.

---

## Install

### Download (recommended)

```bash
TAG=$(curl -fsSL https://api.github.com/repos/skerve/ward-os/releases/latest \
  | grep tag_name | cut -d'"' -f4)
VERSION="${TAG#v}"

curl -fsSL "https://github.com/skerve/ward-os/releases/download/${TAG}/ward-os_${VERSION}_darwin_universal.tar.gz" \
  | tar -xz

# Installs binaries, config, launchd agent, shell hook, and .cursorignore
bash "ward-os_${VERSION}_darwin_universal/install.sh"
```

### Build from source

```bash
git clone https://github.com/skerve/ward-os
cd ward-os
bash scripts/install.sh   # builds + installs everything
```

**Requirements:** macOS 12+, Go 1.22+, Xcode Command Line Tools

---

## Quick start

```bash
ward vault create    # create the encrypted ~/.ward vault (Touch ID / passphrase)
ward status          # check all protection layers
```

---

## Three-tier protection model

```
~/
├── .ward/              TIER 1 — vault          kill always, no exceptions
│
├── Documents/          TIER 2 — protected      kill by default
├── Desktop/                                    ↳ allow-list can grant exceptions
├── Pictures/                                   ↳ Spotlight, Finder, iCloud
├── Movies/                                       are always whitelisted
├── Music/
├── .config/            ← all ~/. dotfolders are tier 2 (auto-discovered)
│
├── .ssh/               TIER 3 — watched        alert only, never kill
├── .aws/                                       (normal tools must always work)
├── .gnupg/
├── ~/Library/          TIER 3 — watched        alert only
├── ~/Downloads/        TIER 3 — watched        alert only (browsers write here)
│
└── Projects/           unprotected             agents work here freely
```

| Tier | Default action | Allow-list override? | Notes |
|---|---|---|---|
| **1 — vault** (`~/.ward`) | Kill | No | Unconditional |
| **2 — protected** (`~/Documents`, `~/Desktop`, dotfolders) | Kill | Yes — `ward allow add` | Spotlight, Finder, iCloud, browsers whitelisted |
| **3 — watched** (`~/.ssh`, `~/Library`, `~/Downloads`, …) | Alert | N/A | Never kill — normal ops must work |

> **Note on enforcement:** The guard is reactive (fsnotify fires *after* access). Kill is reliable for long-running processes; unreliable for fast one-shot reads. It functions as a strong deterrent and a complete audit trail. True preventive blocking requires Apple's Endpoint Security Framework.

---

## Commands

```bash
# Vault
ward vault create            # create and mount ~/.ward (interactive)
ward vault mount             # unlock (Touch ID / passphrase)
ward vault unmount           # lock ~/.ward
ward vault status            # is the vault mounted?

# Secrets
ward secret set openai/key sk-...   # store a secret
ward secret get openai/key          # retrieve
ward secret list                    # list all
ward secret delete openai/key       # delete

# Approvals
ward allow add ~/Documents/project  # grant permanent access
ward allow add ~/Desktop --duration 1h
ward allow list
ward allow revoke 3

# Monitoring
ward status                  # overall protection status
ward logs                    # last 50 violations
ward logs --since 2026-06-01

# Setup
ward ignore install          # write ~/.cursorignore
ward shell-init --install    # install vault auto-check in ~/.zshrc

# Info
ward version
```

---

## Secrets vault (`~/.ward`)

`~/.ward` is an AES-256 encrypted APFS sparsebundle mounted directly at that path. When unmounted it appears empty — no process can read its contents.

`~/.ssh`, `~/.aws`, `~/.gnupg` etc. are **left completely untouched.** `git push`, `ssh`, `aws`, `brew` — all work normally regardless of vault state.

```
~/.ward/
├── keys/       ← API keys, PATs (ward secret set/get)
├── tokens/     ← OAuth tokens
├── certs/      ← TLS certificates
├── env/        ← .env files
└── notes/      ← sensitive notes, seed phrases
```

---

## Shell wrapper for agents

Set `ward-shell` as the shell for agent terminals:

```json
// Cursor settings
"terminal.integrated.profiles.osx": {
  "ward-shell": { "path": "/usr/local/bin/ward-shell" }
}
```

`ward-shell` strips `AWS_*`, `GITHUB_TOKEN`, `SSH_AUTH_SOCK`, `OPENAI_API_KEY`, and 20+ other secret env vars before exec'ing the real shell. It also redirects `$HOME` to `~/ward-sandbox`.

---

## Configuration

`~/.config/ward-os/ward.yaml` — key settings:

| Key | Default | Description |
|---|---|---|
| `vault.mount_point` | `~/.ward` | Where the vault is mounted |
| `vault.auto_unmount_minutes` | `30` | Auto-lock after N idle minutes |
| `guard.zones` | see config | Zone definitions with tier and policy |
| `guard.whitelisted_processes` | 50+ entries | Processes that bypass the guard |
| `shell.strip_env_prefixes` | `AWS_`, `GITHUB_`, … | Env vars stripped in ward-shell |

---

## Development

```bash
git clone https://github.com/skerve/ward-os
cd ward-os
go mod download
CGO_ENABLED=1 go build ./...
CGO_ENABLED=1 go test ./...
```

### Release

Releases are triggered by pushing a version tag:

```bash
git tag v1.2.3
git push origin v1.2.3
```

The release workflow builds arm64 + amd64 binaries on separate macOS runners, combines them into a universal binary with `lipo`, and publishes a GitHub Release.

---

## Uninstall

```bash
launchctl unload ~/Library/LaunchAgents/com.skerve.ward-guard.plist
rm ~/Library/LaunchAgents/com.skerve.ward-guard.plist
ward vault destroy     # ⚠️  deletes vault and all secrets inside
rm /usr/local/bin/ward /usr/local/bin/ward-guard /usr/local/bin/ward-shell
```

---

## License

[MIT](LICENSE) © 2026 [Skerve](https://github.com/skerve)
