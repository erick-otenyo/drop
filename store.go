//go:build !guestonly

package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Store is the on-disk history. Everything is plain text; the file is only
// ever served through the admin page.
type Store struct{ db *sql.DB }

type SessionRow struct {
	ID        int64  `json:"id"`
	Mode      string `json:"mode"`
	StartedAt int64  `json:"startedAt"`
	EndedAt   int64  `json:"endedAt"`
	Count     int    `json:"count"`
	Preview   string `json:"preview"`
}

type MessageRow struct {
	ID   int64  `json:"id"`
	Dir  string `json:"dir"`
	Body string `json:"body"`
	TS   int64  `json:"ts"`
}

func dataDir() (string, error) {
	d := os.Getenv("DROP_DATA_DIR")
	if d == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			return "", err
		}
		d = filepath.Join(base, "drop")
	}
	return d, os.MkdirAll(d, 0o700)
}

func openStore(dir string) (*Store, error) {
	path := filepath.Join(dir, "history.db")
	// Create the file ourselves so it is never group- or world-readable.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	f.Close()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`
		PRAGMA secure_delete = ON;
		CREATE TABLE IF NOT EXISTS sessions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			mode TEXT NOT NULL,
			started_at INTEGER NOT NULL,
			ended_at INTEGER NOT NULL DEFAULT 0
		);
		CREATE TABLE IF NOT EXISTS messages (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			session_id INTEGER NOT NULL REFERENCES sessions(id),
			dir TEXT NOT NULL,
			body TEXT NOT NULL,
			created_at INTEGER NOT NULL
		);
		CREATE INDEX IF NOT EXISTS messages_session ON messages(session_id);
	`)
	if err != nil {
		db.Close()
		return nil, err
	}
	s := &Store{db: db}
	// Only one drop process runs at a time, so any session still marked open
	// was left behind by a crash.
	_, err = db.Exec(`UPDATE sessions SET ended_at = started_at WHERE ended_at = 0`)
	if err == nil {
		_, err = db.Exec(`DELETE FROM sessions WHERE id NOT IN (SELECT session_id FROM messages)`)
	}
	if err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func nowMs() int64 { return time.Now().UnixMilli() }

func (s *Store) NewSession(mode string) (int64, error) {
	r, err := s.db.Exec(`INSERT INTO sessions(mode, started_at) VALUES(?, ?)`, mode, nowMs())
	if err != nil {
		return 0, err
	}
	return r.LastInsertId()
}

// EndSession closes a session, dropping it entirely if nothing was said.
func (s *Store) EndSession(id int64) error {
	if _, err := s.db.Exec(`UPDATE sessions SET ended_at = ? WHERE id = ?`, nowMs(), id); err != nil {
		return err
	}
	_, err := s.db.Exec(`DELETE FROM sessions WHERE id = ? AND NOT EXISTS (SELECT 1 FROM messages WHERE session_id = ?)`, id, id)
	return err
}

func (s *Store) AddMessage(sessionID int64, dir, body string, ts int64) (int64, error) {
	r, err := s.db.Exec(`INSERT INTO messages(session_id, dir, body, created_at) VALUES(?, ?, ?, ?)`, sessionID, dir, body, ts)
	if err != nil {
		return 0, err
	}
	return r.LastInsertId()
}

func (s *Store) DeleteMessage(id int64) error {
	_, err := s.db.Exec(`DELETE FROM messages WHERE id = ?`, id)
	return err
}

func (s *Store) DeleteSession(id int64) error {
	if _, err := s.db.Exec(`DELETE FROM messages WHERE session_id = ?`, id); err != nil {
		return err
	}
	_, err := s.db.Exec(`DELETE FROM sessions WHERE id = ?`, id)
	return err
}

// DeleteAllExcept wipes history, sparing one session (the live one; pass 0
// to spare nothing).
func (s *Store) DeleteAllExcept(keep int64) error {
	if _, err := s.db.Exec(`DELETE FROM messages WHERE session_id != ?`, keep); err != nil {
		return err
	}
	if _, err := s.db.Exec(`DELETE FROM sessions WHERE id != ?`, keep); err != nil {
		return err
	}
	_, err := s.db.Exec(`VACUUM`)
	return err
}

// ListSessions returns sessions newest first. With a query, only sessions
// holding a matching message are returned and the preview is that message.
func (s *Store) ListSessions(q string) ([]SessionRow, error) {
	like := "%" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(q) + "%"
	rows, err := s.db.Query(`
		SELECT s.id, s.mode, s.started_at, s.ended_at,
			(SELECT COUNT(*) FROM messages m WHERE m.session_id = s.id),
			COALESCE((SELECT substr(m.body, 1, 200) FROM messages m
				WHERE m.session_id = s.id AND m.body LIKE ? ESCAPE '\' ORDER BY m.id LIMIT 1), '')
		FROM sessions s
		WHERE ? = '' OR EXISTS (SELECT 1 FROM messages m WHERE m.session_id = s.id AND m.body LIKE ? ESCAPE '\')
		ORDER BY s.id DESC LIMIT 500`, like, q, like)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SessionRow{}
	for rows.Next() {
		var r SessionRow
		if err := rows.Scan(&r.ID, &r.Mode, &r.StartedAt, &r.EndedAt, &r.Count, &r.Preview); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) SessionMessages(id int64) ([]MessageRow, error) {
	rows, err := s.db.Query(`SELECT id, dir, body, created_at FROM messages WHERE session_id = ? ORDER BY id`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []MessageRow{}
	for rows.Next() {
		var r MessageRow
		if err := rows.Scan(&r.ID, &r.Dir, &r.Body, &r.TS); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) Close() error { return s.db.Close() }
