// Package sites manages the applications ("sites") a single ExactusWAF instance
// protects. One WAF process fronts the public port(s) and routes each request
// to the matching site's backend — by Host header (domain-based) and/or by a
// dedicated listener port. This is what lets one dashboard cover many apps on
// one server instead of running a separate WAF per app.
//
// Sites are persisted to <data_dir>/sites.json and changes are fanned out via
// OnChange so the live proxy re-routes without a restart (new listener ports
// still need a restart to open the socket).
package sites

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Site is one protected application.
type Site struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Domains   []string  `json:"domains"` // host-based routing on the shared public port
	Backend   string    `json:"backend"` // http://host:port of the real app
	Port      int       `json:"port"`    // 0 = host-routed only; >0 = dedicated listener
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type persisted struct {
	Sites []Site `json:"sites"`
}

// Store holds the configured sites.
type Store struct {
	mu       sync.RWMutex
	path     string
	sites    map[string]*Site
	order    []string
	onChange func([]Site)
}

// NewStore loads sites.json from path if present, otherwise starts empty.
func NewStore(path string) (*Store, error) {
	s := &Store{path: path, sites: map[string]*Site{}}
	if path == "" {
		return s, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, fmt.Errorf("cannot read sites %q: %w", path, err)
	}
	var p persisted
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("sites file %q is corrupted: %w", path, err)
	}
	for i := range p.Sites {
		site := p.Sites[i]
		s.sites[site.ID] = &site
		s.order = append(s.order, site.ID)
	}
	return s, nil
}

// OnChange registers fn and calls it once with the current list.
func (s *Store) OnChange(fn func([]Site)) {
	if fn == nil {
		return
	}
	s.mu.Lock()
	s.onChange = fn
	list := s.listLocked()
	s.mu.Unlock()
	fn(list)
}

func (s *Store) notifyLocked() {
	if s.onChange != nil {
		s.onChange(s.listLocked())
	}
}

func (s *Store) listLocked() []Site {
	out := make([]Site, 0, len(s.order))
	for _, id := range s.order {
		out = append(out, *s.sites[id])
	}
	return out
}

// List returns all sites in display order.
func (s *Store) List() []Site {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.listLocked()
}

// Get returns one site.
func (s *Store) Get(id string) (Site, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if site, ok := s.sites[id]; ok {
		return *site, true
	}
	return Site{}, false
}

// Ports returns the distinct dedicated listener ports across all sites.
func (s *Store) Ports() []int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	seen := map[int]bool{}
	var out []int
	for _, id := range s.order {
		if p := s.sites[id].Port; p > 0 && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// Create adds a new site.
func (s *Store) Create(in Site) (Site, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	clean, err := s.validate(in, "")
	if err != nil {
		return Site{}, err
	}
	now := time.Now()
	clean.ID = newID()
	clean.CreatedAt = now
	clean.UpdatedAt = now
	s.sites[clean.ID] = &clean
	s.order = append(s.order, clean.ID)
	if err := s.persistLocked(); err != nil {
		delete(s.sites, clean.ID)
		s.order = removeID(s.order, clean.ID)
		return Site{}, err
	}
	s.notifyLocked()
	return clean, nil
}

// Update changes an existing site.
func (s *Store) Update(id string, in Site) (Site, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.sites[id]
	if !ok {
		return Site{}, fmt.Errorf("application not found")
	}
	clean, err := s.validate(in, id)
	if err != nil {
		return Site{}, err
	}
	old := *cur
	clean.ID = id
	clean.CreatedAt = cur.CreatedAt
	clean.UpdatedAt = time.Now()
	*cur = clean
	if err := s.persistLocked(); err != nil {
		*cur = old
		return Site{}, err
	}
	s.notifyLocked()
	return *cur, nil
}

// Delete removes a site.
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.sites[id]; !ok {
		return fmt.Errorf("application not found")
	}
	removed := *s.sites[id]
	delete(s.sites, id)
	s.order = removeID(s.order, id)
	if err := s.persistLocked(); err != nil {
		s.sites[id] = &removed
		s.order = append(s.order, id)
		return err
	}
	s.notifyLocked()
	return nil
}

// validate checks and normalizes a site; ignoreID excludes a site from the
// uniqueness checks (used by Update).
func (s *Store) validate(in Site, ignoreID string) (Site, error) {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		return Site{}, fmt.Errorf("application name is required")
	}
	if len(in.Name) > 64 {
		return Site{}, fmt.Errorf("application name must be at most 64 characters")
	}
	be, err := normalizeBackendURL(in.Backend)
	if err != nil {
		return Site{}, err
	}
	in.Backend = be

	domains := make([]string, 0, len(in.Domains))
	seenDom := map[string]bool{}
	for _, d := range in.Domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}
		if err := validateDomain(d); err != nil {
			return Site{}, err
		}
		if seenDom[d] {
			continue
		}
		seenDom[d] = true
		domains = append(domains, d)
	}
	in.Domains = domains

	if in.Port < 0 || in.Port > 65535 {
		return Site{}, fmt.Errorf("port must be between 0 and 65535")
	}
	if len(in.Domains) == 0 && in.Port == 0 {
		return Site{}, fmt.Errorf("give the application at least one domain or a dedicated port")
	}

	// Uniqueness across other sites: name, each domain, and the port.
	for _, id := range s.order {
		if id == ignoreID {
			continue
		}
		other := s.sites[id]
		if strings.EqualFold(other.Name, in.Name) {
			return Site{}, fmt.Errorf("name %q is already used by another application", in.Name)
		}
		for _, d := range other.Domains {
			if seenDom[d] {
				return Site{}, fmt.Errorf("domain %q is already routed to another application", d)
			}
		}
		if in.Port != 0 && other.Port == in.Port {
			return Site{}, fmt.Errorf("port %d is already used by another application", in.Port)
		}
	}
	return in, nil
}

func (s *Store) persistLocked() error {
	if s.path == "" {
		return nil
	}
	p := persisted{Sites: s.listLocked()}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// normalizeBackendURL accepts "http://host:port" / "https://host:port" and
// returns it trimmed, or errors.
func normalizeBackendURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("backend is required (e.g. http://127.0.0.1:3000)")
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", fmt.Errorf("backend %q must look like http://host:port", raw)
	}
	return strings.TrimRight(raw, "/"), nil
}

func validateDomain(d string) error {
	if strings.ContainsAny(d, "/:") || strings.Contains(d, " ") {
		return fmt.Errorf("domain %q must be a bare hostname (no scheme, port or path)", d)
	}
	if len(d) > 253 {
		return fmt.Errorf("domain %q is too long", d)
	}
	for _, c := range d {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '*' || c == '_') {
			return fmt.Errorf("domain %q has invalid characters", d)
		}
	}
	return nil
}

func newID() string {
	var b [5]byte
	_, _ = rand.Read(b[:])
	return "site-" + hex.EncodeToString(b[:])
}

func removeID(list []string, id string) []string {
	out := list[:0]
	for _, v := range list {
		if v != id {
			out = append(out, v)
		}
	}
	return out
}
