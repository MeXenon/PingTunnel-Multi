package pingtunnel

import (
	"database/sql"
	"path/filepath"
	"testing"
)

func TestServerForwardConfigForKeyUsesPerUserOverride(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "server-forward.db")
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	_, err = db.Exec(`
		CREATE TABLE users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			key INTEGER UNIQUE NOT NULL,
			quota_bytes INTEGER DEFAULT 0,
			used_bytes INTEGER DEFAULT 0,
			max_sessions INTEGER DEFAULT 0,
			forward_proxy TEXT DEFAULT '',
			enabled INTEGER DEFAULT 1,
			is_main INTEGER DEFAULT 0
		)
	`)
	if err != nil {
		t.Fatalf("create users: %v", err)
	}
	for _, row := range []struct {
		username string
		key      int
		forward  string
	}{
		{"inherit", 100000021, ""},
		{"direct", 100000022, "direct"},
		{"socks", 100000023, "socks5://127.0.0.1:1080"},
	} {
		if _, err = db.Exec("INSERT INTO users (username, key, forward_proxy, enabled) VALUES (?, ?, ?, 1)", row.username, row.key, row.forward); err != nil {
			t.Fatalf("insert user %s: %v", row.username, err)
		}
	}
	_ = db.Close()

	am, err := NewAuthManager(dbPath)
	if err != nil {
		t.Fatalf("new auth manager: %v", err)
	}
	t.Cleanup(am.Stop)

	globalForward, err := ParseForwardURL("socks5://127.0.0.1:2080")
	if err != nil {
		t.Fatalf("parse global forward: %v", err)
	}
	server := &Server{useMultiAuth: true, authManager: am, forwardConfig: globalForward}

	if got := server.forwardConfigForKey(100000021); got != globalForward {
		t.Fatalf("inherit key got %#v, want global forward", got)
	}
	if got := server.forwardConfigForKey(100000022); got != nil {
		t.Fatalf("direct key got %#v, want nil direct override", got)
	}
	got := server.forwardConfigForKey(100000023)
	if got == nil || got.Address() != "127.0.0.1:1080" {
		t.Fatalf("socks key got %#v, want per-user forward", got)
	}
}
