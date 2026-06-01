// Package version holds the build-time version metadata injected by GoReleaser
// via -ldflags.
package version

// These variables are overridden at link time by GoReleaser.
// Default values are used during `go run` / local builds.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// String returns a human-readable version string.
func String() string {
	return Version + " (commit " + Commit + ", built " + Date + ")"
}
