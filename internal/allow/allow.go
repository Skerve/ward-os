// Package allow manages a time-limited, path/process-scoped access grant list.
//
// When ward-guard would normally kill a process for touching a protected zone,
// it first checks whether a matching grant exists here. If it does, the access
// is permitted and the event is still logged (with action "allowed").
//
// Grants are stored in the same SQLite database as the audit log.
package allow

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3" // register the sqlite3 driver
)

// Grant represents a single access approval.
type Grant struct {
	ID        int64
	Path      string // protected path prefix this grant covers
	Process   string // "" means any process
	GrantedAt time.Time
	ExpiresAt time.Time // zero means never expires
	Note      string
}

// Store manages the grants table inside the ward-os SQLite database.
type Store struct {
	db *sql.DB
}

// Open opens (or creates) the grants store at dbPath.
// It reuses the same file as the audit database.
func Open(dbPath string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o700); err != nil {
		return nil, fmt.Errorf("creating db dir: %w", err)
	}
	db, err := sql.Open("sqlite3", dbPath+"?_journal=WAL&_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("opening db: %w", err)
	}
	if err := migrate(db); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the underlying database.
func (s *Store) Close() error { return s.db.Close() }

// Add creates a new grant.
func (s *Store) Add(path, process, note string, duration time.Duration) (Grant, error) {
	path = cleanPath(path)
	now := time.Now().UTC()
	var expiresAt time.Time
	if duration > 0 {
		expiresAt = now.Add(duration)
	}

	res, err := s.db.ExecContext(context.Background(), `
		INSERT INTO grants (path, process, granted_at, expires_at, note)
		VALUES (?, ?, ?, ?, ?)`,
		path,
		process,
		now.Format(time.RFC3339),
		nullableTime(expiresAt),
		note,
	)
	if err != nil {
		return Grant{}, fmt.Errorf("inserting grant: %w", err)
	}
	id, _ := res.LastInsertId()
	return Grant{
		ID:        id,
		Path:      path,
		Process:   process,
		GrantedAt: now,
		ExpiresAt: expiresAt,
		Note:      note,
	}, nil
}

// Revoke deletes a grant by ID.
func (s *Store) Revoke(id int64) error {
	res, err := s.db.ExecContext(context.Background(), `DELETE FROM grants WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("no grant found with id %d", id)
	}
	return nil
}

// IsAllowed returns true if a valid, non-expired grant exists for the given
// path and process combination.
func (s *Store) IsAllowed(path, process string) bool {
	path = cleanPath(path)
	now := time.Now().UTC().Format(time.RFC3339)

	rows, err := s.db.QueryContext(context.Background(), `
		SELECT path, process, expires_at
		FROM grants
		WHERE (expires_at IS NULL OR expires_at > ?)
		ORDER BY length(path) DESC`, now)
	if err != nil {
		return false
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var gPath, gProcess string
		var expiresStr sql.NullString
		if err := rows.Scan(&gPath, &gProcess, &expiresStr); err != nil {
			continue
		}
		// Path must be a prefix of the accessed path.
		if !strings.HasPrefix(path, gPath) {
			continue
		}
		// Process must match or grant is for any process.
		if gProcess != "" && !strings.EqualFold(filepath.Base(process), filepath.Base(gProcess)) {
			continue
		}
		return true
	}
	return false
}

// List returns all current (non-expired) grants.
func (s *Store) List() ([]Grant, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	rows, err := s.db.QueryContext(context.Background(), `
		SELECT id, path, process, granted_at, expires_at, note
		FROM grants
		WHERE expires_at IS NULL OR expires_at > ?
		ORDER BY id ASC`, now)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	return scanGrants(rows)
}

// ListAll returns all grants including expired ones.
func (s *Store) ListAll() ([]Grant, error) {
	rows, err := s.db.QueryContext(context.Background(), `
		SELECT id, path, process, granted_at, expires_at, note
		FROM grants ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	return scanGrants(rows)
}

// PurgeExpired removes expired grants.
func (s *Store) PurgeExpired() (int64, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := s.db.ExecContext(context.Background(), `DELETE FROM grants WHERE expires_at IS NOT NULL AND expires_at <= ?`, now)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func scanGrants(rows *sql.Rows) ([]Grant, error) {
	var out []Grant
	for rows.Next() {
		var g Grant
		var grantedStr string
		var expiresStr sql.NullString
		if err := rows.Scan(&g.ID, &g.Path, &g.Process, &grantedStr, &expiresStr, &g.Note); err != nil {
			return nil, err
		}
		g.GrantedAt, _ = time.Parse(time.RFC3339, grantedStr)
		if expiresStr.Valid && expiresStr.String != "" {
			g.ExpiresAt, _ = time.Parse(time.RFC3339, expiresStr.String)
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func migrate(db *sql.DB) error {
	_, err := db.ExecContext(context.Background(), `
		CREATE TABLE IF NOT EXISTS grants (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			path       TEXT    NOT NULL,
			process    TEXT    NOT NULL DEFAULT '',
			granted_at TEXT    NOT NULL,
			expires_at TEXT,
			note       TEXT    NOT NULL DEFAULT ''
		);
		CREATE INDEX IF NOT EXISTS idx_grants_path ON grants(path);
		CREATE INDEX IF NOT EXISTS idx_grants_expires ON grants(expires_at);
	`)
	return err
}

func nullableTime(t time.Time) interface{} {
	if t.IsZero() {
		return nil
	}
	return t.Format(time.RFC3339)
}

func cleanPath(p string) string {
	home, _ := os.UserHomeDir()
	if strings.HasPrefix(p, "~/") {
		p = filepath.Join(home, p[2:])
	} else if p == "~" {
		p = home
	}
	return filepath.Clean(p)
}
