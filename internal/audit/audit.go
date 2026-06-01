// Package audit provides a structured SQLite-backed access log.
package audit

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// Entry represents a single audit event.
type Entry struct {
	ID          int64
	Time        time.Time
	Path        string
	Operation   string
	ProcessName string
	PID         int
	Action      string
}

// Auditor writes and reads audit entries.
type Auditor struct {
	db *sql.DB
}

// Open opens (or creates) the SQLite database at dbPath.
func Open(dbPath string) (*Auditor, error) {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o700); err != nil {
		return nil, fmt.Errorf("creating audit dir: %w", err)
	}

	db, err := sql.Open("sqlite3", dbPath+"?_journal=WAL&_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("opening db: %w", err)
	}

	if err := migrate(db); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}

	return &Auditor{db: db}, nil
}

// Close closes the underlying database connection.
func (a *Auditor) Close() error {
	return a.db.Close()
}

// Log inserts an entry into the audit log.
func (a *Auditor) Log(e Entry) error {
	_, err := a.db.Exec(
		`INSERT INTO events (time, path, operation, process_name, pid, action)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		e.Time.UTC().Format(time.RFC3339Nano),
		e.Path,
		e.Operation,
		e.ProcessName,
		e.PID,
		e.Action,
	)
	return err
}

// Recent returns the most recent n entries (newest first).
func (a *Auditor) Recent(n int) ([]Entry, error) {
	rows, err := a.db.Query(
		`SELECT id, time, path, operation, process_name, pid, action
		 FROM events ORDER BY id DESC LIMIT ?`, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEntries(rows)
}

// Since returns all entries after the given time.
func (a *Auditor) Since(t time.Time) ([]Entry, error) {
	rows, err := a.db.Query(
		`SELECT id, time, path, operation, process_name, pid, action
		 FROM events WHERE time >= ? ORDER BY id ASC`,
		t.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEntries(rows)
}

// Purge deletes events older than retainDays days. Pass 0 to keep everything.
func (a *Auditor) Purge(retainDays int) (int64, error) {
	if retainDays == 0 {
		return 0, nil
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -retainDays).Format(time.RFC3339Nano)
	res, err := a.db.Exec(`DELETE FROM events WHERE time < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func scanEntries(rows *sql.Rows) ([]Entry, error) {
	var out []Entry
	for rows.Next() {
		var e Entry
		var ts string
		if err := rows.Scan(&e.ID, &ts, &e.Path, &e.Operation, &e.ProcessName, &e.PID, &e.Action); err != nil {
			return nil, err
		}
		t, _ := time.Parse(time.RFC3339Nano, ts)
		e.Time = t
		out = append(out, e)
	}
	return out, rows.Err()
}

func migrate(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS events (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			time         TEXT    NOT NULL,
			path         TEXT    NOT NULL,
			operation    TEXT    NOT NULL,
			process_name TEXT    NOT NULL,
			pid          INTEGER NOT NULL,
			action       TEXT    NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_events_time ON events(time);
		CREATE INDEX IF NOT EXISTS idx_events_path ON events(path);
	`)
	return err
}
