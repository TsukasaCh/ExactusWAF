// Package settings holds the runtime-editable part of the WAF configuration:
// rate limiting, auto-ban, and the IP block/allow sets. Unlike config.yaml
// (read once at startup), these can be changed from the console at runtime; the
// store persists them to <data_dir>/settings.json and notifies subscribers so
// the live proxy applies the change without a restart.
package settings

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// RateLimit mirrors config.RateLimitConfig but as the editable, persisted form.
type RateLimit struct {
	Enabled           bool `json:"enabled"`
	RequestsPerMinute int  `json:"requests_per_minute"`
	Burst             int  `json:"burst"`
}

// AutoBan mirrors config.AutoBanConfig as the editable, persisted form.
type AutoBan struct {
	Enabled       bool   `json:"enabled"`
	MaxStrikes    int    `json:"max_strikes"`
	WindowMinutes int    `json:"window_minutes"`
	BanMinutes    int    `json:"ban_minutes"`
	Scope         string `json:"scope"`
}

// Settings is the full editable set.
type Settings struct {
	RateLimit RateLimit `json:"rate_limit"`
	AutoBan   AutoBan   `json:"auto_ban"`
	Blocklist []string  `json:"blocklist"`
	Allowlist []string  `json:"allowlist"`
}

const maxIPEntries = 10000

// Store guards the current Settings, persists them, and fans changes out to
// subscribers (e.g. the proxy).
type Store struct {
	mu       sync.RWMutex
	cur      Settings
	path     string // "" = in-memory only (not persisted)
	onChange []func(Settings)
}

// NewStore loads settings.json from path if present, otherwise seeds from
// defaults (and writes the seed so the file exists). An empty path keeps
// settings in memory only.
func NewStore(path string, defaults Settings) (*Store, error) {
	s := &Store{path: path, cur: sanitize(defaults)}
	if path == "" {
		return s, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, s.persistLocked() // seed the file; ignore nothing-to-read
		}
		return nil, fmt.Errorf("could not read settings %q: %w", path, err)
	}
	var loaded Settings
	if err := json.Unmarshal(data, &loaded); err != nil {
		return nil, fmt.Errorf("invalid settings.json: %w", err)
	}
	s.cur = sanitize(loaded)
	return s, nil
}

// Get returns a copy of the current settings (safe to read/mutate by callers).
func (s *Store) Get() Settings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return clone(s.cur)
}

// OnChange registers fn and calls it once immediately with the current settings
// (so subscribers pick up the persisted state at startup).
func (s *Store) OnChange(fn func(Settings)) {
	if fn == nil {
		return
	}
	s.mu.Lock()
	s.onChange = append(s.onChange, fn)
	cur := clone(s.cur)
	s.mu.Unlock()
	fn(cur)
}

// UpdateShield validates and applies new rate-limit + auto-ban settings.
func (s *Store) UpdateShield(rl RateLimit, ab AutoBan) (Settings, error) {
	if err := validateRateLimit(rl); err != nil {
		return Settings{}, err
	}
	if err := validateAutoBan(ab); err != nil {
		return Settings{}, err
	}
	s.mu.Lock()
	old := s.cur
	s.cur.RateLimit = normalizeRateLimit(rl)
	s.cur.AutoBan = normalizeAutoBan(ab)
	if err := s.persistLocked(); err != nil {
		s.cur = old // roll back so memory, disk and the live proxy stay consistent
		s.mu.Unlock()
		return Settings{}, err
	}
	out := clone(s.cur)
	subs := append([]func(Settings){}, s.onChange...)
	s.mu.Unlock()
	for _, fn := range subs {
		fn(out)
	}
	return out, nil
}

// UpdateIPSets validates (IP or CIDR), normalizes and applies new block/allow
// lists. Returns the normalized settings.
func (s *Store) UpdateIPSets(block, allow []string) (Settings, error) {
	nb, err := normalizeIPList(block)
	if err != nil {
		return Settings{}, fmt.Errorf("blocklist: %w", err)
	}
	na, err := normalizeIPList(allow)
	if err != nil {
		return Settings{}, fmt.Errorf("allowlist: %w", err)
	}
	s.mu.Lock()
	old := s.cur
	s.cur.Blocklist = nb
	s.cur.Allowlist = na
	if err := s.persistLocked(); err != nil {
		s.cur = old // roll back so memory, disk and the live proxy stay consistent
		s.mu.Unlock()
		return Settings{}, err
	}
	out := clone(s.cur)
	subs := append([]func(Settings){}, s.onChange...)
	s.mu.Unlock()
	for _, fn := range subs {
		fn(out)
	}
	return out, nil
}

// persistLocked writes settings.json atomically. Caller must hold s.mu.
func (s *Store) persistLocked() error {
	if s.path == "" {
		return nil
	}
	data, err := json.MarshalIndent(s.cur, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		return fmt.Errorf("could not write settings: %w", err)
	}
	return os.Rename(tmp, s.path)
}

// ---- validation / normalization ----

func validateRateLimit(rl RateLimit) error {
	if !rl.Enabled {
		return nil
	}
	if rl.RequestsPerMinute < 1 || rl.RequestsPerMinute > 1_000_000 {
		return fmt.Errorf("rate limit: requests per minute must be between 1 and 1000000")
	}
	if rl.Burst < 1 || rl.Burst > 1_000_000 {
		return fmt.Errorf("rate limit: burst must be between 1 and 1000000")
	}
	return nil
}

func validateAutoBan(ab AutoBan) error {
	if !ab.Enabled {
		return nil
	}
	if ab.MaxStrikes < 1 || ab.MaxStrikes > 10_000 {
		return fmt.Errorf("auto-ban: strikes must be between 1 and 10000")
	}
	if ab.WindowMinutes < 1 || ab.WindowMinutes > 10_080 {
		return fmt.Errorf("auto-ban: window must be between 1 and 10080 minutes")
	}
	if ab.BanMinutes < 1 || ab.BanMinutes > 525_600 {
		return fmt.Errorf("auto-ban: ban duration must be between 1 and 525600 minutes")
	}
	if ab.Scope != "ip" && ab.Scope != "ip_ua" {
		return fmt.Errorf("auto-ban: scope must be 'ip' or 'ip_ua'")
	}
	return nil
}

func normalizeRateLimit(rl RateLimit) RateLimit {
	if rl.RequestsPerMinute <= 0 {
		rl.RequestsPerMinute = 240
	}
	if rl.Burst <= 0 {
		rl.Burst = 60
	}
	return rl
}

func normalizeAutoBan(ab AutoBan) AutoBan {
	if ab.MaxStrikes <= 0 {
		ab.MaxStrikes = 5
	}
	if ab.WindowMinutes <= 0 {
		ab.WindowMinutes = 10
	}
	if ab.BanMinutes <= 0 {
		ab.BanMinutes = 60
	}
	if ab.Scope != "ip" && ab.Scope != "ip_ua" {
		ab.Scope = "ip_ua"
	}
	return ab
}

// normalizeIPList validates each entry as a single IP or a CIDR, canonicalizes
// it, drops blanks, and de-duplicates while preserving order.
func normalizeIPList(list []string) ([]string, error) {
	out := make([]string, 0, len(list))
	seen := make(map[string]bool)
	for _, raw := range list {
		v := strings.TrimSpace(raw)
		if v == "" {
			continue
		}
		canon, err := canonicalIP(v)
		if err != nil {
			return nil, err
		}
		if seen[canon] {
			continue
		}
		seen[canon] = true
		out = append(out, canon)
		if len(out) > maxIPEntries {
			return nil, fmt.Errorf("too many entries (max %d)", maxIPEntries)
		}
	}
	return out, nil
}

func canonicalIP(v string) (string, error) {
	if strings.Contains(v, "/") {
		_, n, err := net.ParseCIDR(v)
		if err != nil {
			return "", fmt.Errorf("%q is not a valid CIDR (e.g. 10.0.0.0/8)", v)
		}
		return n.String(), nil
	}
	ip := net.ParseIP(v)
	if ip == nil {
		return "", fmt.Errorf("%q is not a valid IP address", v)
	}
	return ip.String(), nil
}

func sanitize(s Settings) Settings {
	s.RateLimit = normalizeRateLimit(s.RateLimit)
	s.AutoBan = normalizeAutoBan(s.AutoBan)
	// Best-effort normalize IP lists; silently drop invalid seed entries.
	if nb, err := normalizeIPList(s.Blocklist); err == nil {
		s.Blocklist = nb
	}
	if na, err := normalizeIPList(s.Allowlist); err == nil {
		s.Allowlist = na
	}
	if s.Blocklist == nil {
		s.Blocklist = []string{}
	}
	if s.Allowlist == nil {
		s.Allowlist = []string{}
	}
	return s
}

func clone(s Settings) Settings {
	s.Blocklist = append([]string{}, s.Blocklist...)
	s.Allowlist = append([]string{}, s.Allowlist...)
	return s
}
