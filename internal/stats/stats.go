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
	TotalCounted  uint64
	TotalAllowed  uint64
	StartedAt     time.Time

	byCategory map[string]uint64
	bySeverity map[string]uint64
	byIP       map[string]uint64
	byRule     map[string]*RuleHit
	bySite     map[string]*SiteStat // traffic per protected app

	buckets map[int64]*bucket // deret waktu per menit (kunci = unix menit)

	recent []Event
	max    int
}

// bucket menyimpan jumlah per menit untuk grafik lalu lintas.
type bucket struct {
	allowed uint64
	blocked uint64
	counted uint64
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

// SiteStat is per-app traffic (requests seen and requests blocked).
type SiteStat struct {
	Requests uint64 `json:"requests"`
	Blocked  uint64 `json:"blocked"`
}

func New() *Store {
	return &Store{
		StartedAt:  time.Now(),
		byCategory: make(map[string]uint64),
		bySeverity: make(map[string]uint64),
		byIP:       make(map[string]uint64),
		byRule:     make(map[string]*RuleHit),
		bySite:     make(map[string]*SiteStat),
		buckets:    make(map[int64]*bucket),
		max:        200,
	}
}

// RecordSite attributes one request to a protected app.
func (s *Store) RecordSite(site string, blocked bool) {
	if site == "" {
		site = "default"
	}
	s.mu.Lock()
	st, ok := s.bySite[site]
	if !ok {
		st = &SiteStat{}
		s.bySite[site] = st
	}
	st.Requests++
	if blocked {
		st.Blocked++
	}
	s.mu.Unlock()
}

// SiteStats returns a copy of per-app traffic keyed by app name.
func (s *Store) SiteStats() map[string]SiteStat {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]SiteStat, len(s.bySite))
	for k, v := range s.bySite {
		out[k] = *v
	}
	return out
}

// bucketAt mengambil/membuat bucket untuk menit dari t (dipanggil saat s.mu terkunci).
func (s *Store) bucketAt(t time.Time) *bucket {
	key := t.Unix() / 60
	b, ok := s.buckets[key]
	if !ok {
		b = &bucket{}
		s.buckets[key] = b
		// Buang bucket yang lebih tua dari ~2 jam agar peta tidak membengkak.
		if len(s.buckets) > 160 {
			cutoff := key - 150
			for k := range s.buckets {
				if k < cutoff {
					delete(s.buckets, k)
				}
			}
		}
	}
	return b
}

func (s *Store) IncRequest() {
	s.mu.Lock()
	s.TotalRequests++
	s.mu.Unlock()
}

func (s *Store) IncAllowed() {
	s.mu.Lock()
	s.TotalAllowed++
	s.bucketAt(time.Now()).allowed++
	s.mu.Unlock()
}

// enforced membedakan aksi yang benar-benar memblokir dari yang hanya dihitung.
func enforced(action string) bool {
	switch action {
	case "blocked", "ip-blocked", "rate-limited", "auto-banned":
		return true
	}
	return false
}

// RecordBlock mencatat sebuah event deteksi (blokir maupun hitung/pantau).
func (s *Store) RecordBlock(e Event, category string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	when := e.Time
	if when.IsZero() {
		when = time.Now()
	}
	if enforced(e.Action) {
		s.TotalBlocked++
		s.bucketAt(when).blocked++
	} else {
		s.TotalCounted++
		s.bucketAt(when).counted++
	}
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
	TotalCounted  uint64            `json:"total_counted"`
	TotalAllowed  uint64            `json:"total_allowed"`
	UptimeSeconds int64             `json:"uptime_seconds"`
	ByCategory    map[string]uint64 `json:"by_category"`
	BySeverity    map[string]uint64 `json:"by_severity"`
	TopIPs        []IPCount         `json:"top_ips"`
	Rules         []RuleHit         `json:"rules"`
	Recent        []Event           `json:"recent"`
}

// SeriesPoint adalah satu titik deret waktu per menit untuk grafik.
type SeriesPoint struct {
	TimeMs  int64  `json:"t"` // awal menit, unix milidetik (mudah dipakai di JS)
	Allowed uint64 `json:"allowed"`
	Blocked uint64 `json:"blocked"`
	Counted uint64 `json:"counted"`
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
		TotalCounted:  s.TotalCounted,
		TotalAllowed:  s.TotalAllowed,
		UptimeSeconds: int64(time.Since(s.StartedAt).Seconds()),
		ByCategory:    cat,
		BySeverity:    sev,
		TopIPs:        top,
		Rules:         rules,
		Recent:        recent,
	}
}

// Series mengembalikan deret waktu per menit untuk n menit terakhir (termasuk
// menit berjalan), menit paling lama di urutan awal. Menit tanpa data berisi nol.
func (s *Store) Series(n int) []SeriesPoint {
	if n <= 0 {
		n = 60
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	nowMin := time.Now().Unix() / 60
	out := make([]SeriesPoint, 0, n)
	for i := n - 1; i >= 0; i-- {
		key := nowMin - int64(i)
		p := SeriesPoint{TimeMs: key * 60 * 1000}
		if b, ok := s.buckets[key]; ok {
			p.Allowed, p.Blocked, p.Counted = b.allowed, b.blocked, b.counted
		}
		out = append(out, p)
	}
	return out
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
