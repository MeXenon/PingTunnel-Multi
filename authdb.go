package pingtunnel

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/esrrhs/gohome/loggo"
	_ "github.com/mattn/go-sqlite3"
)

const (
	MaxKey     = 2147483647
	MinKey     = 100000000
	BytesPerGB = 1073741824
)

const (
	envSessionTimeout       = "PINGTUNNEL_SESSION_TIMEOUT"
	envSessionHandoff       = "PINGTUNNEL_SESSION_HANDOFF"
	envUserReloadInterval   = "PINGTUNNEL_USER_RELOAD"
	defaultSessionTimeout   = 60 * time.Second
	defaultSessionHandoff   = 5 * time.Second
	defaultUserReloadPeriod = 1 * time.Second
)

var (
	ErrInvalidKey    = errors.New("invalid key")
	ErrUserDisabled  = errors.New("user is disabled")
	ErrQuotaExceeded = errors.New("quota exceeded")
	ErrSessionExists = errors.New("user already has active session")
)

// AuthUser represents a user from the database
type AuthUser struct {
	ID         int64
	Username   string
	Key        int64
	QuotaBytes int64
	UsedBytes  int64
	Enabled    bool
	IsMain     bool
}

// AuthManager handles multi-user authentication and traffic accounting
type AuthManager struct {
	db        *sql.DB
	userCache map[int64]*AuthUser // key -> user
	mu        sync.RWMutex

	// Session tracking: key -> clientIP
	activeSessions map[int64]*SessionInfo
	sessionMu      sync.RWMutex

	// Per-user traffic accounting
	userTraffic map[int64]*UserTraffic
	trafficMu   sync.RWMutex

	flushInterval           time.Duration
	userReloadInterval      time.Duration
	sessionTimeout          time.Duration
	sessionHandoffTimeout   time.Duration
	sessionCleanupInterval  time.Duration
	sessionDBUpdateInterval time.Duration
	sessionDBEnabled        bool
	stopChan                chan struct{}
}

type SessionInfo struct {
	UserID       int64
	ClientIP     string
	LastActive   time.Time
	LastDBUpdate time.Time
}

type UserTraffic struct {
	SentBytes int64
	RecvBytes int64
}

// NewAuthManager creates a new auth manager with database path
func NewAuthManager(dbPath string) (*AuthManager, error) {
	db, err := sql.Open("sqlite3", dbPath+"?_foreign_keys=on")
	if err != nil {
		return nil, err
	}

	sessionTimeout := durationFromEnv(envSessionTimeout, defaultSessionTimeout)
	sessionHandoff := durationFromEnv(envSessionHandoff, defaultSessionHandoff)
	userReload := durationFromEnv(envUserReloadInterval, defaultUserReloadPeriod)

	am := &AuthManager{
		db:                      db,
		userCache:               make(map[int64]*AuthUser),
		activeSessions:          make(map[int64]*SessionInfo),
		userTraffic:             make(map[int64]*UserTraffic),
		flushInterval:           10 * time.Second,
		userReloadInterval:      userReload,
		sessionTimeout:          sessionTimeout,
		sessionHandoffTimeout:   sessionHandoff,
		sessionCleanupInterval:  10 * time.Second,
		sessionDBUpdateInterval: 10 * time.Second,
		sessionDBEnabled:        true,
		stopChan:                make(chan struct{}),
	}

	if err := am.loadUsers(); err != nil {
		return nil, err
	}

	if err := am.ensureSessionTable(); err != nil {
		loggo.Error("failed to ensure session table: %s", err.Error())
		am.sessionDBEnabled = false
	} else {
		am.clearActiveSessions()
	}

	// Start background goroutines
	go am.flushTrafficLoop()
	go am.maintenanceLoop()

	return am, nil
}

// loadUsers loads all users from database into cache
func (am *AuthManager) loadUsers() error {
	rows, err := am.db.Query(`
		SELECT id, username, key, quota_bytes, used_bytes, enabled, is_main
		FROM users WHERE enabled = 1
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	am.mu.Lock()
	defer am.mu.Unlock()

	am.userCache = make(map[int64]*AuthUser)
	for rows.Next() {
		var u AuthUser
		var enabled, isMain int
		if err := rows.Scan(&u.ID, &u.Username, &u.Key, &u.QuotaBytes, &u.UsedBytes, &enabled, &isMain); err != nil {
			return err
		}
		u.Enabled = enabled == 1
		u.IsMain = isMain == 1
		am.userCache[u.Key] = &u
	}

	return nil
}

// ValidateKey checks if a key is valid and returns the user
func (am *AuthManager) ValidateKey(key int) (*AuthUser, error) {
	am.mu.RLock()
	user, ok := am.userCache[int64(key)]
	am.mu.RUnlock()

	if !ok {
		return nil, ErrInvalidKey
	}

	if !user.Enabled {
		return nil, ErrUserDisabled
	}

	// Check quota (get fresh from memory including accumulated traffic)
	am.trafficMu.RLock()
	traffic := am.userTraffic[user.ID]
	am.trafficMu.RUnlock()

	totalUsed := user.UsedBytes
	if traffic != nil {
		totalUsed += traffic.SentBytes + traffic.RecvBytes
	}

	if totalUsed >= user.QuotaBytes {
		if user.QuotaBytes <= 0 {
			return user, nil
		}
		return nil, ErrQuotaExceeded
	}

	return user, nil
}

// CanConnect checks if user can connect (single session enforcement)
func (am *AuthManager) CanConnect(key int, clientIP string) bool {
	now := time.Now()

	am.sessionMu.RLock()
	info, exists := am.activeSessions[int64(key)]
	am.sessionMu.RUnlock()

	if !exists {
		return true
	}

	if now.Sub(info.LastActive) > am.sessionTimeout {
		am.sessionMu.Lock()
		delete(am.activeSessions, int64(key))
		am.sessionMu.Unlock()
		am.deleteSessionRow(info.UserID)
		return true
	}

	// Allow same IP (reconnection)
	if info.ClientIP == clientIP {
		return true
	}

	// Allow fast handoff if the previous session has been idle briefly
	if am.sessionHandoffTimeout > 0 && now.Sub(info.LastActive) > am.sessionHandoffTimeout {
		loggo.Info("Session handoff for key %d from %s to %s after %s idle",
			key, info.ClientIP, clientIP, now.Sub(info.LastActive).Truncate(time.Millisecond))
		return true
	}

	return false
}

// TouchSession updates (or creates) the session entry for a key.
func (am *AuthManager) TouchSession(key int, userID int64, clientIP string) {
	now := time.Now()
	var needsDBUpdate bool
	var needsInsert bool

	am.sessionMu.Lock()
	info, exists := am.activeSessions[int64(key)]
	if !exists {
		info = &SessionInfo{
			UserID:     userID,
			ClientIP:   clientIP,
			LastActive: now,
		}
		am.activeSessions[int64(key)] = info
		am.sessionMu.Unlock()
		am.upsertSessionRow(info)
		return
	}

	info.LastActive = now
	if info.UserID == 0 && userID != 0 {
		info.UserID = userID
		info.LastDBUpdate = time.Time{}
		needsInsert = true
	}
	if info.ClientIP != clientIP {
		info.ClientIP = clientIP
		info.LastDBUpdate = time.Time{}
	}
	if now.Sub(info.LastDBUpdate) >= am.sessionDBUpdateInterval {
		info.LastDBUpdate = now
		needsDBUpdate = true
	}
	am.sessionMu.Unlock()

	if needsInsert {
		am.upsertSessionRow(info)
		return
	}
	if needsDBUpdate {
		am.touchSessionRow(info)
	}
}

// RegisterSession registers a new session (legacy alias).
func (am *AuthManager) RegisterSession(key int, clientIP string) {
	am.mu.RLock()
	user, ok := am.userCache[int64(key)]
	am.mu.RUnlock()
	if ok {
		am.TouchSession(key, user.ID, clientIP)
		return
	}
	am.TouchSession(key, 0, clientIP)
}

// UnregisterSession removes a session.
func (am *AuthManager) UnregisterSession(key int) {
	// Rely on session timeout for cleanup to avoid premature removal
	// when multiple connections are active.
}

// AddTraffic adds traffic to a user's account
func (am *AuthManager) AddTraffic(userID int64, sent, recv int64) {
	am.trafficMu.Lock()
	traffic, exists := am.userTraffic[userID]
	if !exists {
		traffic = &UserTraffic{}
		am.userTraffic[userID] = traffic
	}
	traffic.SentBytes += sent
	traffic.RecvBytes += recv
	am.trafficMu.Unlock()
}

// flushTrafficLoop periodically flushes traffic to database
func (am *AuthManager) flushTrafficLoop() {
	ticker := time.NewTicker(am.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-am.stopChan:
			am.flushTraffic()
			return
		case <-ticker.C:
			am.flushTraffic()
		}
	}
}

func (am *AuthManager) flushTraffic() {
	am.trafficMu.Lock()
	trafficToFlush := am.userTraffic
	am.userTraffic = make(map[int64]*UserTraffic)
	am.trafficMu.Unlock()

	for userID, traffic := range trafficToFlush {
		totalBytes := traffic.SentBytes + traffic.RecvBytes
		if totalBytes > 0 {
			_, err := am.db.Exec(`
				UPDATE users SET used_bytes = used_bytes + ?, updated_at = CURRENT_TIMESTAMP
				WHERE id = ?
			`, totalBytes, userID)
			if err != nil {
				loggo.Error("failed to update used_bytes for user %d: %s", userID, err.Error())
			}
			_, err = am.db.Exec(`
				INSERT INTO usage_log (user_id, bytes_sent, bytes_recv)
				VALUES (?, ?, ?)
			`, userID, traffic.SentBytes, traffic.RecvBytes)
			if err != nil {
				loggo.Error("failed to insert usage_log for user %d: %s", userID, err.Error())
			}
		}
	}

	// Reload users to get fresh data
	am.loadUsers()
}

// maintenanceLoop periodically reloads users and cleans up stale sessions.
func (am *AuthManager) maintenanceLoop() {
	ticker := time.NewTicker(am.userReloadInterval)
	defer ticker.Stop()

	for {
		select {
		case <-am.stopChan:
			return
		case <-ticker.C:
			am.loadUsers()
			am.cleanupSessions()
		}
	}
}

func (am *AuthManager) cleanupSessions() {
	now := time.Now()
	var staleUserIDs []int64

	am.sessionMu.Lock()
	for key, info := range am.activeSessions {
		if now.Sub(info.LastActive) > am.sessionTimeout {
			delete(am.activeSessions, key)
			staleUserIDs = append(staleUserIDs, info.UserID)
			continue
		}

		am.mu.RLock()
		_, exists := am.userCache[key]
		am.mu.RUnlock()
		if !exists {
			delete(am.activeSessions, key)
			staleUserIDs = append(staleUserIDs, info.UserID)
		}
	}
	am.sessionMu.Unlock()

	for _, userID := range staleUserIDs {
		am.deleteSessionRow(userID)
	}
}

// Stop stops the auth manager
func (am *AuthManager) Stop() {
	close(am.stopChan)
	am.db.Close()
}

// GetActiveSessionCount returns count of active sessions
func (am *AuthManager) GetActiveSessionCount() int {
	am.sessionMu.RLock()
	defer am.sessionMu.RUnlock()
	return len(am.activeSessions)
}

// GetUserCount returns total user count
func (am *AuthManager) GetUserCount() int {
	am.mu.RLock()
	defer am.mu.RUnlock()
	return len(am.userCache)
}

// GetActiveKeys returns a list of all active user keys
func (am *AuthManager) GetActiveKeys() []int {
	am.mu.RLock()
	defer am.mu.RUnlock()

	keys := make([]int, 0, len(am.userCache))
	for k, u := range am.userCache {
		if u.Enabled {
			keys = append(keys, int(k))
		}
	}
	return keys
}

func (am *AuthManager) ensureSessionTable() error {
	_, err := am.db.Exec(`
		CREATE TABLE IF NOT EXISTS active_sessions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			client_ip TEXT NOT NULL,
			connection_id TEXT NOT NULL,
			started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			last_active DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_sessions_user ON active_sessions(user_id);
		CREATE INDEX IF NOT EXISTS idx_sessions_conn ON active_sessions(connection_id);
		CREATE TABLE IF NOT EXISTS usage_log (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			bytes_sent INTEGER DEFAULT 0,
			bytes_recv INTEGER DEFAULT 0,
			logged_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_usage_log_user ON usage_log(user_id);
		CREATE INDEX IF NOT EXISTS idx_usage_log_time ON usage_log(logged_at);
	`)
	return err
}

func (am *AuthManager) clearActiveSessions() {
	if !am.sessionDBEnabled {
		return
	}
	_, err := am.db.Exec("DELETE FROM active_sessions")
	if err != nil {
		loggo.Error("failed to clear active_sessions: %s", err.Error())
	}
}

func (am *AuthManager) upsertSessionRow(info *SessionInfo) {
	if !am.sessionDBEnabled || info.UserID == 0 {
		return
	}
	connectionID := fmt.Sprintf("user:%d", info.UserID)
	_, err := am.db.Exec("DELETE FROM active_sessions WHERE user_id = ?", info.UserID)
	if err != nil {
		loggo.Error("failed to delete old session row: %s", err.Error())
		return
	}
	_, err = am.db.Exec(`
		INSERT INTO active_sessions (user_id, client_ip, connection_id)
		VALUES (?, ?, ?)
	`, info.UserID, info.ClientIP, connectionID)
	if err != nil {
		loggo.Error("failed to insert session row: %s", err.Error())
	}
}

func (am *AuthManager) touchSessionRow(info *SessionInfo) {
	if !am.sessionDBEnabled || info.UserID == 0 {
		return
	}
	_, err := am.db.Exec(`
		UPDATE active_sessions
		SET client_ip = ?, last_active = CURRENT_TIMESTAMP
		WHERE user_id = ?
	`, info.ClientIP, info.UserID)
	if err != nil {
		loggo.Error("failed to update session row: %s", err.Error())
	}
}

func (am *AuthManager) deleteSessionRow(userID int64) {
	if !am.sessionDBEnabled || userID == 0 {
		return
	}
	_, err := am.db.Exec("DELETE FROM active_sessions WHERE user_id = ?", userID)
	if err != nil {
		loggo.Error("failed to delete session row: %s", err.Error())
	}
}

func durationFromEnv(key string, fallback time.Duration) time.Duration {
	val := strings.TrimSpace(os.Getenv(key))
	if val == "" {
		return fallback
	}
	d, err := time.ParseDuration(val)
	if err != nil || d <= 0 {
		loggo.Error("invalid duration for %s: %s (using %s)", key, val, fallback.String())
		return fallback
	}
	return d
}
