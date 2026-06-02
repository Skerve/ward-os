// Package guard watches the home directory zones and enforces the three-tier
// access policy:
//
//	Tier 1 (~/.ward)       — kill on any unauthorised access, no exceptions.
//	Tier 2 (Documents, Desktop, dotfolders, …) — kill by default, but a grant
//	                        from the allow-list overrides the kill.
//	Tier 3 (~/.ssh, ~/.aws, ~/Library, ~/Downloads, …) — alert only, never kill.
//
// # Reactive kill — an important limitation
//
// This guard is REACTIVE. fsnotify fires after the kernel has already
// delivered the file operation to the process. This means:
//
//  1. For fast reads (open → read → close in <50ms), lsof will return nothing
//     because the file descriptor is already closed. PID=0, nothing to kill.
//  2. For writes/creates, the file content may already be written by the time
//     we kill the process.
//  3. Process name attribution via lsof+ps adds ~10–50ms of latency per event
//     and introduces a further race window.
//
// The practical effect is:
//   - Kill is reliable for long-running processes that hold files open
//     (e.g. an agent that mounts or repeatedly reads a directory).
//   - Kill is unreliable for one-shot reads (the agent may have already
//     finished reading by the time the guard fires).
//   - The audit log is always written, regardless of kill success.
//
// True preventive blocking requires the macOS Endpoint Security Framework
// (ESF), which needs a signed System Extension and Apple approval.
// This guard provides best-effort enforcement plus a complete audit trail.
package guard

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/gen2brain/beeep"

	"github.com/skerve/ward-os/internal/allow"
	"github.com/skerve/ward-os/internal/audit"
	"github.com/skerve/ward-os/internal/config"
)

// Event records a single access violation.
type Event struct {
	Time        time.Time
	Path        string
	Op          fsnotify.Op
	ProcessName string
	PID         int
	Action      string // "alerted", "killed", "allowed (grant)"
	Tier        int
}

// Guard watches paths and enforces the zone policy.
type Guard struct {
	cfg       config.GuardConfig
	watcher   *fsnotify.Watcher
	auditor   *audit.Auditor
	grants    *allow.Store
	whitelist map[string]bool
	// zoneIndex maps watched path prefix → Zone (longest first for matching).
	zoneIndex []zonedPath
	mu        sync.Mutex
	done      chan struct{}
}

type zonedPath struct {
	path string
	zone config.Zone
}

// New creates a Guard. Pass nil auditor/grants to disable those features.
func New(cfg config.GuardConfig, a *audit.Auditor, g *allow.Store) (*Guard, error) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("fsnotify: %w", err)
	}

	wl := make(map[string]bool, len(cfg.WhitelistedProcesses))
	for _, p := range cfg.WhitelistedProcesses {
		wl[strings.ToLower(p)] = true
	}

	return &Guard{
		cfg:       cfg,
		watcher:   w,
		auditor:   a,
		grants:    g,
		whitelist: wl,
		done:      make(chan struct{}),
	}, nil
}

// AddWatchZones registers all zones from config, auto-discovering dotfolders
// for zones with dotfolders_only: true.
func (g *Guard) AddWatchZones() error {
	home, _ := os.UserHomeDir()
	added := 0

	for _, zone := range g.cfg.Zones {
		if zone.DotfoldersOnly {
			// Discover all ~/.<name> directories and files.
			n, err := g.addDotEntries(home, zone)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warn: dotfolder discovery error: %v\n", err)
			}
			added += n
			continue
		}

		if err := g.addZonePath(zone.Path, zone); err != nil {
			fmt.Fprintf(os.Stderr, "warn: cannot watch %s: %v\n", zone.Path, err)
			continue
		}
		added++
	}

	// Also register any legacy watch_paths (backward compat).
	for _, p := range g.cfg.WatchPaths {
		p = config.ExpandHome(p)
		synthetic := config.Zone{Path: p, Tier: 3, OnViolation: "alert"}
		_ = g.addZonePath(p, synthetic)
	}

	if added == 0 {
		return fmt.Errorf("no zone paths could be added")
	}

	// Sort zoneIndex longest-path-first for most-specific match.
	g.mu.Lock()
	sort.Slice(g.zoneIndex, func(i, j int) bool {
		return len(g.zoneIndex[i].path) > len(g.zoneIndex[j].path)
	})
	g.mu.Unlock()

	fmt.Printf("ward-guard: watching %d path(s) across %d zone(s)\n",
		added, len(g.cfg.Zones))
	return nil
}

func (g *Guard) addDotEntries(home string, zone config.Zone) (int, error) {
	entries, err := os.ReadDir(home)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, ".") {
			continue
		}
		// Skip the vault mount point — it is registered as its own tier-1 zone.
		// Skip . and ..
		if name == "." || name == ".." {
			continue
		}
		dotPath := filepath.Join(home, name)
		z := zone
		z.Path = dotPath
		if err := g.addZonePath(dotPath, z); err != nil {
			continue
		}
		n++
	}
	return n, nil
}

func (g *Guard) addZonePath(path string, zone config.Zone) error {
	path = config.ExpandHome(path)
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}

	var watchErr error
	if info.IsDir() {
		watchErr = filepath.Walk(path, func(p string, fi os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if fi.IsDir() {
				return g.watcher.Add(p)
			}
			return nil
		})
	} else {
		watchErr = g.watcher.Add(path)
	}

	if watchErr != nil {
		return watchErr
	}

	g.mu.Lock()
	g.zoneIndex = append(g.zoneIndex, zonedPath{path: path, zone: zone})
	g.mu.Unlock()
	return nil
}

// Run starts the event loop. Blocks until Stop is called.
func (g *Guard) Run() {
	home, _ := os.UserHomeDir()

	// Watch the home directory itself so we can register new dotfolders
	// as they are created after startup (e.g. installing a new CLI tool that
	// writes its own ~/.<name> config dir).
	_ = g.watcher.Add(home)

	for {
		select {
		case <-g.done:
			return
		case event, ok := <-g.watcher.Events:
			if !ok {
				return
			}
			// If a new dotfolder/file is created directly in ~/, register it.
			if event.Op&fsnotify.Create != 0 {
				name := filepath.Base(event.Name)
				if strings.HasPrefix(name, ".") && filepath.Dir(event.Name) == home {
					g.registerNewDotEntry(event.Name)
				}
			}
			g.handleEvent(event)
		case err, ok := <-g.watcher.Errors:
			if !ok {
				return
			}
			fmt.Fprintf(os.Stderr, "watcher error: %v\n", err)
		}
	}
}

// registerNewDotEntry adds a newly created dotfolder/file at ~/ to the
// watch list using the same tier-2 policy as the dotfolders_only zone.
func (g *Guard) registerNewDotEntry(path string) {
	// Find the dotfolders_only zone to copy its policy.
	var dotZone *config.Zone
	for i := range g.cfg.Zones {
		if g.cfg.Zones[i].DotfoldersOnly {
			dotZone = &g.cfg.Zones[i]
			break
		}
	}
	if dotZone == nil {
		return
	}

	// Check it is not already registered.
	g.mu.Lock()
	for _, zp := range g.zoneIndex {
		if zp.path == path {
			g.mu.Unlock()
			return
		}
	}
	g.mu.Unlock()

	z := *dotZone
	z.Path = path
	z.DotfoldersOnly = false
	if err := g.addZonePath(path, z); err != nil {
		return
	}

	// Re-sort zoneIndex after adding.
	g.mu.Lock()
	sort.Slice(g.zoneIndex, func(i, j int) bool {
		return len(g.zoneIndex[i].path) > len(g.zoneIndex[j].path)
	})
	g.mu.Unlock()

	fmt.Printf("ward-guard: registered new dotentry %s (tier-%d)\n", path, z.Tier)
}

// Stop shuts down the guard.
func (g *Guard) Stop() {
	close(g.done)
	_ = g.watcher.Close()
}

func (g *Guard) handleEvent(e fsnotify.Event) {
	if e.Op == fsnotify.Chmod {
		return
	}

	pids := openingPIDs(e.Name)
	if len(pids) == 0 {
		pids = []int{0}
	}

	zone := g.zoneFor(e.Name)

	for _, pid := range pids {
		procName := processName(pid)
		if g.isWhitelisted(procName) {
			continue
		}

		ev := Event{
			Time:        time.Now(),
			Path:        e.Name,
			Op:          e.Op,
			ProcessName: procName,
			PID:         pid,
			Tier:        zone.Tier,
		}

		g.mu.Lock()
		action := g.enforce(ev, zone)
		ev.Action = action
		g.mu.Unlock()

		g.report(ev, zone)

		if g.auditor != nil {
			_ = g.auditor.Log(audit.Entry{
				Time:        ev.Time,
				Path:        ev.Path,
				Operation:   ev.Op.String(),
				ProcessName: ev.ProcessName,
				PID:         ev.PID,
				Action:      ev.Action,
			})
		}
	}
}

func (g *Guard) isWhitelisted(name string) bool {
	if name == "" {
		return false
	}
	return g.whitelist[strings.ToLower(filepath.Base(name))]
}

func (g *Guard) zoneFor(path string) config.Zone {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, zp := range g.zoneIndex {
		if strings.HasPrefix(path, zp.path) {
			return zp.zone
		}
	}
	// Default: treated as tier 3 (alert only).
	return config.Zone{Tier: 3, OnViolation: "alert"}
}

func (g *Guard) enforce(ev Event, zone config.Zone) string {
	policy := zone.OnViolation
	if policy == "" {
		policy = g.cfg.OnViolation
	}
	if policy == "" {
		policy = "alert"
	}

	if policy != "kill" {
		return "alerted"
	}

	// Tier 1 (vault): kill unconditionally, allow-list cannot override.
	if zone.Tier == 1 {
		return g.kill(ev.PID)
	}

	// Tier 2: check allow-list before killing.
	if g.grants != nil && g.grants.IsAllowed(ev.Path, ev.ProcessName) {
		return "allowed (grant)"
	}

	return g.kill(ev.PID)
}

func (g *Guard) kill(pid int) string {
	if pid > 0 {
		if proc, err := os.FindProcess(pid); err == nil {
			_ = proc.Kill()
			return "killed"
		}
	}
	return "alerted"
}

func (g *Guard) report(ev Event, zone config.Zone) {
	tierLabel := map[int]string{1: "vault", 2: "protected", 3: "watched"}[zone.Tier]
	if tierLabel == "" {
		tierLabel = "zone"
	}

	msg := fmt.Sprintf("[tier-%d/%s] %q (PID %d) %s → %s",
		zone.Tier, tierLabel, ev.ProcessName, ev.PID, ev.Op, ev.Path)

	title := g.cfg.NotificationTitle
	if title == "" {
		title = "ward-os alert"
	}

	fmt.Fprintln(os.Stderr, title+": "+msg)

	hint := ""
	if zone.Tier == 2 && ev.Action == "killed" {
		hint = fmt.Sprintf("\nTo allow: ward allow add %q", ev.Path)
	}

	_ = beeep.Alert(title, msg+hint, "")
}

// openingPIDs returns the PIDs that currently have the given path open.
func openingPIDs(path string) []int {
	out, err := exec.CommandContext(context.Background(), "lsof", "-t", "--", path).Output()
	if err != nil {
		return nil
	}
	var pids []int
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if pid, err := strconv.Atoi(line); err == nil {
			pids = append(pids, pid)
		}
	}
	return pids
}

// processName returns the executable name for a PID.
func processName(pid int) string {
	if pid == 0 {
		return "unknown"
	}
	out, err := exec.CommandContext(context.Background(), "ps", "-p", strconv.Itoa(pid), "-o", "comm=").Output()
	if err != nil {
		return "unknown"
	}
	return filepath.Base(strings.TrimSpace(string(out)))
}
