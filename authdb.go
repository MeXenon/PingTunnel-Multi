package pingtunnel

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/esrrhs/pingtunnel/internal/loggo"
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
	ID          int64
	Username    string
	Key         int64
	QuotaBytes  int64
	UsedBytes   int64
	MaxSessions int
	ForwardURL  string
	Forward     *ForwardConfig
	ForwardSet  bool
	Enabled     bool
	IsMain      bool
}

// AuthManager handles multi-user authentication and traffic accounting
type AuthManager struct {
	db        *sql.DB
	userCache map[int64]*AuthUser // key -> user
	mu        sync.RWMutex

	// Session tracking: key/clientIP -> session. A user key may be active from
	// multiple client IPs unless an explicit product-level limit is added.
	activeSessions map[string]*SessionInfo
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
	Key          int64
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
		activeSessions:          make(map[string]*SessionInfo),
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

	if err := am.ensureUserLimitColumns(); err != nil {
		return nil, err
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
		SELECT id, username, key, quota_bytes, used_bytes, COALESCE(max_sessions, 0), COALESCE(forward_proxy, ''), enabled, is_main
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
		if err := rows.Scan(&u.ID, &u.Username, &u.Key, &u.QuotaBytes, &u.UsedBytes, &u.MaxSessions, &u.ForwardURL, &enabled, &isMain); err != nil {
			return err
		}
		if u.MaxSessions < 0 {
			u.MaxSessions = 0
		}
		u.ForwardURL = strings.TrimSpace(u.ForwardURL)
		if u.ForwardURL != "" {
			u.ForwardSet = true
			if isDirectForwardURL(u.ForwardURL) {
				u.Forward = nil
			} else {
				forward, err := ParseForwardURL(u.ForwardURL)
				if err != nil {
					loggo.Error("invalid forward_proxy for user %s key %d: %s", u.Username, u.Key, err.Error())
					u.ForwardSet = false
					u.ForwardURL = ""
				} else {
					u.Forward = forward
				}
			}
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

// CanConnect checks if user can connect.
func (am *AuthManager) CanConnect(key int, clientIP string) bool {
	now := time.Now()
	key64 := int64(key)
	sessionID := sessionMapKey(int64(key), clientIP)

	am.mu.RLock()
	user := am.userCache[key64]
	maxSessions := 0
	userID := int64(0)
	if user != nil {
		maxSessions = user.MaxSessions
		userID = user.ID
	}
	am.mu.RUnlock()

	var staleSessions []SessionInfo
	var reserved *SessionInfo
	allowed := true

	am.sessionMu.Lock()
	if info, exists := am.activeSessions[sessionID]; exists {
		if now.Sub(info.LastActive) <= am.sessionTimeout {
			am.sessionMu.Unlock()
			return true
		}
		delete(am.activeSessions, sessionID)
		staleSessions = append(staleSessions, *info)
	}

	if maxSessions > 0 {
		activeForUser := 0
		for id, info := range am.activeSessions {
			if now.Sub(info.LastActive) > am.sessionTimeout {
				delete(am.activeSessions, id)
				staleSessions = append(staleSessions, *info)
				continue
			}
			if info.Key == key64 {
				activeForUser++
			}
		}
		if activeForUser >= maxSessions {
			allowed = false
		} else {
			reserved = &SessionInfo{
				Key:        key64,
				UserID:     userID,
				ClientIP:   clientIP,
				LastActive: now,
			}
			am.activeSessions[sessionID] = reserved
		}
	}
	am.sessionMu.Unlock()

	for _, info := range staleSessions {
		am.deleteSessionRow(info.UserID, info.ClientIP)
	}
	if reserved != nil {
		am.upsertSessionRow(reserved)
	}
	return allowed
}

// TouchSession updates (or creates) the session entry for a key/client IP.
func (am *AuthManager) TouchSession(key int, userID int64, clientIP string) {
	now := time.Now()
	var needsDBUpdate bool
	var needsInsert bool
	sessionID := sessionMapKey(int64(key), clientIP)

	am.sessionMu.Lock()
	info, exists := am.activeSessions[sessionID]
	if !exists {
		info = &SessionInfo{
			Key:        int64(key),
			UserID:     userID,
			ClientIP:   clientIP,
			LastActive: now,
		}
		am.activeSessions[sessionID] = info
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
	var staleSessions []SessionInfo

	am.mu.RLock()
	users := make(map[int64]AuthUser, len(am.userCache))
	for key, user := range am.userCache {
		if user == nil {
			continue
		}
		users[key] = *user
	}
	am.mu.RUnlock()

	type trackedSession struct {
		id   string
		info *SessionInfo
	}
	byKey := make(map[int64][]trackedSession)

	am.sessionMu.Lock()
	for sessionID, info := range am.activeSessions {
		if now.Sub(info.LastActive) > am.sessionTimeout {
			delete(am.activeSessions, sessionID)
			staleSessions = append(staleSessions, *info)
			continue
		}

		_, exists := users[info.Key]
		if !exists {
			delete(am.activeSessions, sessionID)
			staleSessions = append(staleSessions, *info)
			continue
		}
		byKey[info.Key] = append(byKey[info.Key], trackedSession{id: sessionID, info: info})
	}
	for key, sessions := range byKey {
		user := users[key]
		if user.MaxSessions <= 0 || len(sessions) <= user.MaxSessions {
			continue
		}
		sort.SliceStable(sessions, func(i, j int) bool {
			return sessions[i].info.LastActive.After(sessions[j].info.LastActive)
		})
		for _, session := range sessions[user.MaxSessions:] {
			if current, ok := am.activeSessions[session.id]; ok {
				delete(am.activeSessions, session.id)
				staleSessions = append(staleSessions, *current)
			}
		}
	}
	am.sessionMu.Unlock()

	for _, info := range staleSessions {
		am.deleteSessionRow(info.UserID, info.ClientIP)
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

// ForwardForKey returns a user's explicit forward override. The boolean is
// false when the user should inherit the process-level forward configuration.
func (am *AuthManager) ForwardForKey(key int) (*ForwardConfig, bool) {
	am.mu.RLock()
	defer am.mu.RUnlock()

	user := am.userCache[int64(key)]
	if user == nil || !user.Enabled || !user.ForwardSet {
		return nil, false
	}
	return user.Forward, true
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

func (am *AuthManager) ensureUserLimitColumns() error {
	var name string
	err := am.db.QueryRow("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'users'").Scan(&name)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}

	rows, err := am.db.Query("PRAGMA table_info(users)")
	if err != nil {
		return err
	}
	defer rows.Close()

	hasMaxSessions := false
	hasForwardProxy := false
	for rows.Next() {
		var cid int
		var columnName, columnType string
		var notNull, pk int
		var defaultValue any
		if err := rows.Scan(&cid, &columnName, &columnType, &notNull, &defaultValue, &pk); err != nil {
			return err
		}
		if strings.EqualFold(columnName, "max_sessions") {
			hasMaxSessions = true
		}
		if strings.EqualFold(columnName, "forward_proxy") {
			hasForwardProxy = true
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if !hasMaxSessions {
		if _, err := am.db.Exec("ALTER TABLE users ADD COLUMN max_sessions INTEGER DEFAULT 0"); err != nil {
			return err
		}
	}
	if !hasForwardProxy {
		if _, err := am.db.Exec("ALTER TABLE users ADD COLUMN forward_proxy TEXT DEFAULT ''"); err != nil {
			return err
		}
	}
	return nil
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
	connectionID := sessionConnectionID(info.UserID, info.ClientIP)
	_, err := am.db.Exec("DELETE FROM active_sessions WHERE user_id = ? AND client_ip = ?", info.UserID, info.ClientIP)
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
		SET last_active = CURRENT_TIMESTAMP
		WHERE user_id = ? AND client_ip = ?
	`, info.UserID, info.ClientIP)
	if err != nil {
		loggo.Error("failed to update session row: %s", err.Error())
	}
}

func (am *AuthManager) deleteSessionRow(userID int64, clientIP string) {
	if !am.sessionDBEnabled || userID == 0 {
		return
	}
	_, err := am.db.Exec("DELETE FROM active_sessions WHERE user_id = ? AND client_ip = ?", userID, clientIP)
	if err != nil {
		loggo.Error("failed to delete session row: %s", err.Error())
	}
}

func sessionMapKey(key int64, clientIP string) string {
	return fmt.Sprintf("%d|%s", key, strings.TrimSpace(clientIP))
}

func sessionConnectionID(userID int64, clientIP string) string {
	return fmt.Sprintf("user:%d:%s", userID, strings.TrimSpace(clientIP))
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
