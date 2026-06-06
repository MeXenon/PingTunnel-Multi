package pingtunnel

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func newSessionLimitAuthManager(t *testing.T, users ...testAuthUser) (*AuthManager, *sql.DB) {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "auth.db")
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	_, err = db.Exec(`
		CREATE TABLE users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			key INTEGER UNIQUE NOT NULL,
			quota_bytes INTEGER DEFAULT 0,
			used_bytes INTEGER DEFAULT 0,
			max_sessions INTEGER DEFAULT 0,
			enabled INTEGER DEFAULT 1,
			is_main INTEGER DEFAULT 0
		)
	`)
	if err != nil {
		t.Fatalf("create users: %v", err)
	}
	for _, user := range users {
		_, err = db.Exec(
			"INSERT INTO users (username, key, max_sessions, enabled) VALUES (?, ?, ?, 1)",
			user.username,
			user.key,
			user.maxSessions,
		)
		if err != nil {
			t.Fatalf("insert user: %v", err)
		}
	}
	_ = db.Close()

	am, err := NewAuthManager(dbPath)
	if err != nil {
		t.Fatalf("new auth manager: %v", err)
	}
	t.Cleanup(am.Stop)

	checkDB, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("reopen db: %v", err)
	}
	t.Cleanup(func() { _ = checkDB.Close() })
	return am, checkDB
}

type testAuthUser struct {
	username    string
	key         int
	maxSessions int
}

func TestAuthManagerUnlimitedSessionsWhenMaxIsZero(t *testing.T) {
	am, _ := newSessionLimitAuthManager(t, testAuthUser{username: "unlimited", key: 100000001, maxSessions: 0})

	for _, ip := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		if !am.CanConnect(100000001, ip) {
			t.Fatalf("expected unlimited user to connect from %s", ip)
		}
		am.TouchSession(100000001, 1, ip)
	}
}

func TestAuthManagerEnforcesPerUserSessionCap(t *testing.T) {
	am, _ := newSessionLimitAuthManager(t, testAuthUser{username: "capped", key: 100000002, maxSessions: 2})

	if !am.CanConnect(100000002, "10.0.0.1") {
		t.Fatal("first session should connect")
	}
	am.TouchSession(100000002, 1, "10.0.0.1")
	if !am.CanConnect(100000002, "10.0.0.2") {
		t.Fatal("second session should connect")
	}
	am.TouchSession(100000002, 1, "10.0.0.2")
	if am.CanConnect(100000002, "10.0.0.3") {
		t.Fatal("third distinct session should be rejected")
	}
	if !am.CanConnect(100000002, "10.0.0.1") {
		t.Fatal("existing session should refresh even at cap")
	}
}

func TestAuthManagerSessionCapIsIsolatedPerUser(t *testing.T) {
	am, _ := newSessionLimitAuthManager(
		t,
		testAuthUser{username: "one", key: 100000003, maxSessions: 1},
		testAuthUser{username: "two", key: 100000004, maxSessions: 1},
	)

	am.TouchSession(100000003, 1, "10.0.0.1")
	if am.CanConnect(100000003, "10.0.0.2") {
		t.Fatal("second session for first user should be rejected")
	}
	if !am.CanConnect(100000004, "10.0.0.2") {
		t.Fatal("first user's cap must not block second user")
	}
}

func TestAuthManagerStaleSessionFreesCapSlot(t *testing.T) {
	am, _ := newSessionLimitAuthManager(t, testAuthUser{username: "stale", key: 100000005, maxSessions: 1})
	am.sessionTimeout = time.Second
	am.TouchSession(100000005, 1, "10.0.0.1")

	am.sessionMu.Lock()
	for _, info := range am.activeSessions {
		info.LastActive = time.Now().Add(-2 * time.Second)
	}
	am.sessionMu.Unlock()

	if !am.CanConnect(100000005, "10.0.0.2") {
		t.Fatal("stale session should not consume the user cap")
	}
}

func TestAuthManagerLoweredCapDropsOnlyThatUsersExcessSessions(t *testing.T) {
	am, db := newSessionLimitAuthManager(
		t,
		testAuthUser{username: "resize", key: 100000006, maxSessions: 3},
		testAuthUser{username: "other", key: 100000007, maxSessions: 0},
	)

	am.TouchSession(100000006, 1, "10.0.0.1")
	am.TouchSession(100000006, 1, "10.0.0.2")
	am.TouchSession(100000006, 1, "10.0.0.3")
	am.TouchSession(100000007, 2, "10.0.0.4")

	if _, err := db.Exec("UPDATE users SET max_sessions = 1 WHERE key = ?", 100000006); err != nil {
		t.Fatalf("lower cap: %v", err)
	}
	if err := am.loadUsers(); err != nil {
		t.Fatalf("reload users: %v", err)
	}
	am.cleanupSessions()

	am.sessionMu.RLock()
	defer am.sessionMu.RUnlock()
	resizeCount := 0
	otherCount := 0
	for _, info := range am.activeSessions {
		if info.Key == 100000006 {
			resizeCount++
		}
		if info.Key == 100000007 {
			otherCount++
		}
	}
	if resizeCount != 1 {
		t.Fatalf("expected one resized-user session after cap cleanup, got %d", resizeCount)
	}
	if otherCount != 1 {
		t.Fatalf("other user's session should remain, got %d", otherCount)
	}
}

func TestAuthManagerMigratesLegacyUsersWithoutMaxSessions(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "legacy-auth.db")
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
			enabled INTEGER DEFAULT 1,
			is_main INTEGER DEFAULT 0
		)
	`)
	if err != nil {
		t.Fatalf("create legacy users table: %v", err)
	}
	if _, err = db.Exec("INSERT INTO users (username, key, enabled) VALUES ('legacy', 100000008, 1)"); err != nil {
		t.Fatalf("insert legacy user: %v", err)
	}
	_ = db.Close()

	am, err := NewAuthManager(dbPath)
	if err != nil {
		t.Fatalf("new auth manager: %v", err)
	}
	t.Cleanup(am.Stop)

	checkDB, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("reopen db: %v", err)
	}
	defer checkDB.Close()

	var maxSessions int
	if err := checkDB.QueryRow("SELECT max_sessions FROM users WHERE username = 'legacy'").Scan(&maxSessions); err != nil {
		t.Fatalf("read migrated max_sessions: %v", err)
	}
	if maxSessions != 0 {
		t.Fatalf("legacy max_sessions = %d, want 0", maxSessions)
	}
	var forwardProxy string
	if err := checkDB.QueryRow("SELECT forward_proxy FROM users WHERE username = 'legacy'").Scan(&forwardProxy); err != nil {
		t.Fatalf("read migrated forward_proxy: %v", err)
	}
	if forwardProxy != "" {
		t.Fatalf("legacy forward_proxy = %q, want empty", forwardProxy)
	}
	if user := am.userCache[100000008]; user == nil || user.MaxSessions != 0 {
		t.Fatalf("legacy user cache = %#v, want max_sessions 0", user)
	}
}

func TestAuthManagerLoadsPerUserForwardOverrides(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "forward-auth.db")
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
		{"inherit", 100000009, ""},
		{"direct", 100000010, "direct"},
		{"socks", 100000011, "socks5://127.0.0.1:1080"},
		{"invalid", 100000012, "ftp://127.0.0.1:21"},
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

	if cfg, ok := am.ForwardForKey(100000009); ok || cfg != nil {
		t.Fatalf("inherit user returned cfg=%#v ok=%v, want no override", cfg, ok)
	}
	if cfg, ok := am.ForwardForKey(100000010); !ok || cfg != nil {
		t.Fatalf("direct user returned cfg=%#v ok=%v, want direct override", cfg, ok)
	}
	cfg, ok := am.ForwardForKey(100000011)
	if !ok || cfg == nil || cfg.Scheme != "socks5" || cfg.Address() != "127.0.0.1:1080" {
		t.Fatalf("socks user returned cfg=%#v ok=%v, want socks5 override", cfg, ok)
	}
	if cfg, ok := am.ForwardForKey(100000012); ok || cfg != nil {
		t.Fatalf("invalid user returned cfg=%#v ok=%v, want ignored override", cfg, ok)
	}
}
