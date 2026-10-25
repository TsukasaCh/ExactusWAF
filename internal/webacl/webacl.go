// Package webacl mengelola Web ACL: kumpulan signature terpilih beserta aksinya
// (block/count), mirip Web ACL di AWS WAF. Satu Web ACL berstatus aktif dan
// menjadi rencana (plan) yang dipakai mesin WAF secara langsung.
package webacl

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"exactuswaf/internal/waf"
)

// RuleRef adalah satu signature yang dipilih dalam Web ACL beserta aksinya.
type RuleRef struct {
	SignatureID string `json:"signature_id"`
	Action      string `json:"action"` // "block" | "count"
}

// ACL adalah satu Web ACL.
type ACL struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Rules       []RuleRef `json:"rules"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// persisted adalah bentuk yang disimpan ke disk.
type persisted struct {
	ActiveID string `json:"active_id"`
	ACLs     []ACL  `json:"acls"`
}

// Store menyimpan semua Web ACL dan menentukan mana yang aktif.
type Store struct {
	mu       sync.RWMutex
	path     string // "" = tanpa persistensi (hanya di memori)
	cat      *waf.Catalog
	acls     map[string]*ACL
	order    []string // urutan tampil
	activeID string
	onChange func(*waf.Plan)
}

// NewStore memuat Web ACL dari path (bila ada) atau membuat satu Web ACL
// "default" berisi SEMUA signature beraksi block. path kosong = tanpa simpan.
func NewStore(path string, cat *waf.Catalog) (*Store, error) {
	s := &Store{path: path, cat: cat, acls: map[string]*ACL{}}
	loaded := false
	if path != "" {
		if data, err := os.ReadFile(path); err == nil {
			if err := s.load(data); err != nil {
				return nil, fmt.Errorf("Web ACL file %q is corrupted: %w", path, err)
			}
			loaded = true
		} else if !os.IsNotExist(err) {
			return nil, fmt.Errorf("cannot read %q: %w", path, err)
		}
	}
	if !loaded {
		def := s.defaultACL()
		s.acls[def.ID] = def
		s.order = []string{def.ID}
		s.activeID = def.ID
		if err := s.persist(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *Store) defaultACL() *ACL {
	now := time.Now()
	acl := &ACL{
		ID: "acl-default", Name: "default",
		Description: "Default Web ACL: all signatures active and blocking.",
		CreatedAt:   now, UpdatedAt: now,
	}
	for _, sig := range s.cat.Signatures() {
		acl.Rules = append(acl.Rules, RuleRef{SignatureID: sig.ID, Action: string(waf.ActionBlock)})
	}
	return acl
}

func (s *Store) load(data []byte) error {
	var p persisted
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	if len(p.ACLs) == 0 {
		return fmt.Errorf("no Web ACL")
	}
	for i := range p.ACLs {
		a := p.ACLs[i]
		// Buang signature yang tak lagi ada di katalog (mis. setelah update aturan).
		a.Rules = s.cleanRules(a.Rules)
		s.acls[a.ID] = &a
		s.order = append(s.order, a.ID)
	}
	s.activeID = p.ActiveID
	if _, ok := s.acls[s.activeID]; !ok {
		s.activeID = s.order[0]
	}
	return nil
}

// cleanRules membuang referensi signature yang tidak dikenal dan aksi tak valid.
func (s *Store) cleanRules(in []RuleRef) []RuleRef {
	seen := map[string]bool{}
	var out []RuleRef
	for _, r := range in {
		if !s.cat.Has(r.SignatureID) || seen[r.SignatureID] {
			continue
		}
		if !waf.ValidAction(waf.Action(r.Action)) {
			r.Action = string(waf.ActionBlock)
		}
		seen[r.SignatureID] = true
		out = append(out, r)
	}
	return out
}

// persist menulis keadaan ke disk secara atomik (tulis sementara lalu rename).
// Harus dipanggil dengan s.mu terkunci.
func (s *Store) persist() error {
	if s.path == "" {
		return nil
	}
	p := persisted{ActiveID: s.activeID}
	for _, id := range s.order {
		p.ACLs = append(p.ACLs, *s.acls[id])
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// OnChange mendaftarkan callback yang dipanggil dengan plan Web ACL aktif yang
// baru setiap kali ada perubahan (dan sekali saat dipanggil, untuk inisialisasi).
func (s *Store) OnChange(fn func(*waf.Plan)) {
	s.mu.Lock()
	s.onChange = fn
	plan := s.planLocked()
	s.mu.Unlock()
	fn(plan)
}

// planLocked menyusun plan untuk Web ACL aktif. Harus dipanggil dengan s.mu terkunci.
func (s *Store) planLocked() *waf.Plan {
	acl := s.acls[s.activeID]
	specs := make([]waf.PlanSpec, 0, len(acl.Rules))
	for _, r := range acl.Rules {
		specs = append(specs, waf.PlanSpec{SignatureID: r.SignatureID, Action: waf.Action(r.Action)})
	}
	return s.cat.BuildPlan(specs)
}

// Plan mengembalikan plan Web ACL aktif saat ini.
func (s *Store) Plan() *waf.Plan {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.planLocked()
}

func (s *Store) notify() {
	if s.onChange != nil {
		s.onChange(s.planLocked())
	}
}

// List mengembalikan semua Web ACL sesuai urutan tampil.
func (s *Store) List() []ACL {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ACL, 0, len(s.order))
	for _, id := range s.order {
		out = append(out, *s.acls[id])
	}
	return out
}

// Get mengembalikan satu Web ACL.
func (s *Store) Get(id string) (ACL, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if a, ok := s.acls[id]; ok {
		return *a, true
	}
	return ACL{}, false
}

// ActiveID mengembalikan id Web ACL aktif.
func (s *Store) ActiveID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.activeID
}

// Active mengembalikan Web ACL aktif.
func (s *Store) Active() ACL {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return *s.acls[s.activeID]
}

func newID() string {
	var b [5]byte
	_, _ = rand.Read(b[:])
	return "acl-" + hex.EncodeToString(b[:])
}

// validateInput memeriksa nama dan daftar rule untuk Create/Update.
func (s *Store) validateInput(name string, rules []RuleRef, ignoreID string) ([]RuleRef, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("Web ACL name is required")
	}
	if len(name) > 64 {
		return nil, fmt.Errorf("Web ACL name must be at most 64 characters")
	}
	for _, id := range s.order {
		if id != ignoreID && strings.EqualFold(s.acls[id].Name, name) {
			return nil, fmt.Errorf("name %q is already used by another Web ACL", name)
		}
	}
	for _, r := range rules {
		if !s.cat.Has(r.SignatureID) {
			return nil, fmt.Errorf("signature %q is not in the catalog", r.SignatureID)
		}
		if !waf.ValidAction(waf.Action(r.Action)) {
			return nil, fmt.Errorf("action %q is invalid (must be block or count)", r.Action)
		}
	}
	clean := s.cleanRules(rules)
	// Web ACL kosong akan mematikan seluruh proteksi bila diaktifkan.
	if len(clean) == 0 {
		return nil, fmt.Errorf("select at least one signature")
	}
	return clean, nil
}

// Create membuat Web ACL baru (tidak otomatis aktif).
func (s *Store) Create(name, desc string, rules []RuleRef) (ACL, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	clean, err := s.validateInput(name, rules, "")
	if err != nil {
		return ACL{}, err
	}
	now := time.Now()
	acl := &ACL{
		ID: newID(), Name: strings.TrimSpace(name), Description: strings.TrimSpace(desc),
		Rules: clean, CreatedAt: now, UpdatedAt: now,
	}
	s.acls[acl.ID] = acl
	s.order = append(s.order, acl.ID)
	if err := s.persist(); err != nil {
		// Gagal menyimpan ke disk: batalkan perubahan di memori agar tetap konsisten.
		delete(s.acls, acl.ID)
		s.order = remove(s.order, acl.ID)
		return ACL{}, err
	}
	return *acl, nil
}

// Update mengubah nama, deskripsi, dan daftar rule sebuah Web ACL. Bila yang
// diubah adalah Web ACL aktif, plan mesin WAF ikut diperbarui.
func (s *Store) Update(id, name, desc string, rules []RuleRef) (ACL, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	acl, ok := s.acls[id]
	if !ok {
		return ACL{}, fmt.Errorf("Web ACL not found")
	}
	clean, err := s.validateInput(name, rules, id)
	if err != nil {
		return ACL{}, err
	}
	old := *acl
	acl.Name = strings.TrimSpace(name)
	acl.Description = strings.TrimSpace(desc)
	acl.Rules = clean
	acl.UpdatedAt = time.Now()
	if err := s.persist(); err != nil {
		*acl = old // kembalikan ke keadaan semula bila gagal menyimpan ke disk
		return ACL{}, err
	}
	if id == s.activeID {
		s.notify()
	}
	return *acl, nil
}

// Delete menghapus Web ACL. Web ACL aktif tidak boleh dihapus.
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.acls[id]; !ok {
		return fmt.Errorf("Web ACL not found")
	}
	if id == s.activeID {
		return fmt.Errorf("cannot delete the active Web ACL — activate another one first")
	}
	if len(s.order) <= 1 {
		return fmt.Errorf("at least one Web ACL is required")
	}
	delete(s.acls, id)
	s.order = remove(s.order, id)
	return s.persist()
}

// SetActive menjadikan sebuah Web ACL aktif dan memperbarui plan mesin WAF.
func (s *Store) SetActive(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.acls[id]; !ok {
		return fmt.Errorf("Web ACL not found")
	}
	if id == s.activeID {
		return nil
	}
	s.activeID = id
	if err := s.persist(); err != nil {
		return err
	}
	s.notify()
	return nil
}

func remove(list []string, id string) []string {
	out := list[:0]
	for _, v := range list {
		if v != id {
			out = append(out, v)
		}
	}
	return out
}

// Capacity meniru WCU AWS secara sederhana: bobot tiap signature berdasarkan
// targetnya (semakin luas target, semakin "mahal").
func Capacity(cat *waf.Catalog, rules []RuleRef) int {
	total := 0
	for _, r := range rules {
		sig, ok := cat.Get(r.SignatureID)
		if !ok {
			continue
		}
		switch sig.Target {
		case "all":
			total += 3
		case "body":
			total += 2
		default:
			total++
		}
	}
	return total
}

// MaxCapacity adalah batas kapasitas sebuah Web ACL (seperti 1500 WCU di AWS).
const MaxCapacity = 1500

// SortRefsByCatalog mengurutkan RuleRef sesuai urutan signature di katalog, agar
// evaluasi konsisten tak peduli urutan input.
func SortRefsByCatalog(cat *waf.Catalog, rules []RuleRef) {
	idx := map[string]int{}
	for i, sig := range cat.Signatures() {
		idx[sig.ID] = i
	}
	sort.SliceStable(rules, func(i, j int) bool { return idx[rules[i].SignatureID] < idx[rules[j].SignatureID] })
}
