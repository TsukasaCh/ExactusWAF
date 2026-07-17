// Package stats mengumpulkan metrik dan log serangan untuk dashboard.
package stats

import (
	"sync"
	"time"
)

// Event adalah satu catatan permintaan yang diblokir/diamati.
type Event struct {
	Time     time.Time `json:"time"`
	IP       string    `json:"ip"`
	Method   string    `json:"method"`
	Path     string    `json:"path"`
	RuleID   string    `json:"rule_id"`
	RuleName string    `json:"rule_name"`
	CVE      string    `json:"cve"`
	Severity string    `json:"severity"`
	Action   string    `json:"action"` // blocked | monitored | rate-limited | ip-blocked
}

// Store menyimpan counter agregat dan event terbaru (ring buffer).
type Store struct {
	mu sync.RWMutex

	TotalRequests uint64
	TotalBlocked  uint64
	TotalAllowed  uint64
	StartedAt     time.Time

	byCategory map[string]uint64
	bySeverity map[string]uint64
	byIP       map[string]uint64
	byRule     map[string]*RuleHit

	recent []Event
	max    int
}

// RuleHit adalah rekap satu aturan yang pernah terpicu.
type RuleHit struct {
	RuleID   string    `json:"rule_id"`
	RuleName string    `json:"rule_name"`
	CVE      string    `json:"cve"`
	Severity string    `json:"severity"`
	Category string    `json:"category"`
	Count    uint64    `json:"count"`
	LastSeen time.Time `json:"last_seen"`
}

func New() *Store {
	return &Store{
		StartedAt:  time.Now(),
		byCategory: make(map[string]uint64),
		bySeverity: make(map[string]uint64),
		byIP:       make(map[string]uint64),
		byRule:     make(map[string]*RuleHit),
		max:        200,
	}
}

func (s *Store) IncRequest() {
	s.mu.Lock()
	s.TotalRequests++
	s.mu.Unlock()
}

func (s *Store) IncAllowed() {
	s.mu.Lock()
	s.TotalAllowed++
	s.mu.Unlock()
}

// RecordBlock mencatat sebuah event serangan.
func (s *Store) RecordBlock(e Event, category string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.TotalBlocked++
	if category != "" {
		s.byCategory[category]++
	}
	if e.Severity != "" {
		s.bySeverity[e.Severity]++
	}
	if e.IP != "" {
		s.byIP[e.IP]++
	}
	if e.RuleID != "" {
		rh, ok := s.byRule[e.RuleID]
		if !ok {
			rh = &RuleHit{
				RuleID: e.RuleID, RuleName: e.RuleName, CVE: e.CVE,
				Severity: e.Severity, Category: category,
			}
			s.byRule[e.RuleID] = rh
		}
		rh.Count++
		rh.LastSeen = e.Time
	}
	s.recent = append(s.recent, e)
	if len(s.recent) > s.max {
		s.recent = s.recent[len(s.recent)-s.max:]
	}
}

// Snapshot adalah salinan aman data untuk dirender ke JSON dashboard.
type Snapshot struct {
	TotalRequests uint64            `json:"total_requests"`
	TotalBlocked  uint64            `json:"total_blocked"`
	TotalAllowed  uint64            `json:"total_allowed"`
	UptimeSeconds int64             `json:"uptime_seconds"`
	ByCategory    map[string]uint64 `json:"by_category"`
	BySeverity    map[string]uint64 `json:"by_severity"`
	TopIPs        []IPCount         `json:"top_ips"`
	Rules         []RuleHit         `json:"rules"`
	Recent        []Event           `json:"recent"`
}

type IPCount struct {
	IP    string `json:"ip"`
	Count uint64 `json:"count"`
}

func (s *Store) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cat := make(map[string]uint64, len(s.byCategory))
	for k, v := range s.byCategory {
		cat[k] = v
	}
	sev := make(map[string]uint64, len(s.bySeverity))
	for k, v := range s.bySeverity {
		sev[k] = v
	}

	// Ambil event terbaru dulu (urut terbalik).
	recent := make([]Event, 0, len(s.recent))
	for i := len(s.recent) - 1; i >= 0; i-- {
		recent = append(recent, s.recent[i])
	}

	top := topIPs(s.byIP, 15)

	// Rekap per-aturan, urut dari yang paling sering.
	rules := make([]RuleHit, 0, len(s.byRule))
	for _, rh := range s.byRule {
		rules = append(rules, *rh)
	}
	for i := 0; i < len(rules); i++ {
		for j := i + 1; j < len(rules); j++ {
			if rules[j].Count > rules[i].Count {
				rules[i], rules[j] = rules[j], rules[i]
			}
		}
	}

	return Snapshot{
		TotalRequests: s.TotalRequests,
		TotalBlocked:  s.TotalBlocked,
		TotalAllowed:  s.TotalAllowed,
		UptimeSeconds: int64(time.Since(s.StartedAt).Seconds()),
		ByCategory:    cat,
		BySeverity:    sev,
		TopIPs:        top,
		Rules:         rules,
		Recent:        recent,
	}
}

func topIPs(m map[string]uint64, n int) []IPCount {
	list := make([]IPCount, 0, len(m))
	for ip, c := range m {
		list = append(list, IPCount{IP: ip, Count: c})
	}
	// Selection-ish sort sederhana (n kecil).
	for i := 0; i < len(list); i++ {
		for j := i + 1; j < len(list); j++ {
			if list[j].Count > list[i].Count {
				list[i], list[j] = list[j], list[i]
			}
		}
	}
	if len(list) > n {
		list = list[:n]
	}
	return list
}
