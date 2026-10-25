package webacl

import (
	"strings"
	"testing"

	"exactuswaf/internal/waf"
)

func newStore(t *testing.T) (*Store, *waf.Catalog) {
	t.Helper()
	cat, err := waf.LoadCatalog("")
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewStore("", cat) // in-memory
	if err != nil {
		t.Fatal(err)
	}
	return s, cat
}

func TestSeedDefaultBerisiSemuaSignature(t *testing.T) {
	s, cat := newStore(t)
	a := s.Active()
	if a.Name != "default" || len(a.Rules) != cat.Count() {
		t.Fatalf("default ACL: nama %q, %d rules (katalog %d)", a.Name, len(a.Rules), cat.Count())
	}
	if s.Plan().Len() != cat.Count() {
		t.Fatalf("plan aktif %d, harusnya %d", s.Plan().Len(), cat.Count())
	}
}

func TestWebACLKosongDitolak(t *testing.T) {
	s, _ := newStore(t)
	if _, err := s.Create("kosong", "", nil); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("ACL tanpa rule harusnya ditolak, dapat %v", err)
	}
	// Rule yang semuanya tidak dikenal juga berakhir kosong -> ditolak.
	bogus := []RuleRef{{SignatureID: "TIDAK-ADA", Action: "block"}}
	if _, err := s.Create("bogus", "", bogus); err == nil {
		t.Fatal("ACL dengan signature tak dikenal harusnya ditolak")
	}
}

func TestCreateAktifkanHapus(t *testing.T) {
	s, cat := newStore(t)
	sig := cat.Signatures()[0].ID
	a, err := s.Create("khusus", "uji", []RuleRef{{SignatureID: sig, Action: "count"}})
	if err != nil {
		t.Fatal(err)
	}
	if a.ID == s.ActiveID() {
		t.Fatal("ACL baru tidak boleh langsung aktif")
	}

	var planLen int
	s.OnChange(func(p *waf.Plan) { planLen = p.Len() })
	if err := s.SetActive(a.ID); err != nil {
		t.Fatal(err)
	}
	if s.ActiveID() != a.ID || planLen != 1 {
		t.Fatalf("setelah aktivasi: active=%s planLen=%d", s.ActiveID(), planLen)
	}
	// ACL aktif tidak boleh dihapus.
	if err := s.Delete(a.ID); err == nil {
		t.Fatal("ACL aktif seharusnya tidak bisa dihapus")
	}
	// Aktifkan default lagi lalu hapus yang khusus.
	if err := s.SetActive("acl-default"); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(a.ID); err != nil {
		t.Fatalf("hapus ACL non-aktif gagal: %v", err)
	}
}

func TestCapacity(t *testing.T) {
	_, cat := newStore(t)
	// Satu signature target "all" berbobot 3.
	var all string
	for _, s := range cat.Signatures() {
		if s.Target == "all" {
			all = s.ID
			break
		}
	}
	if all == "" {
		t.Skip("tidak ada signature target all")
	}
	if c := Capacity(cat, []RuleRef{{SignatureID: all, Action: "block"}}); c != 3 {
		t.Fatalf("kapasitas signature 'all' = %d, harusnya 3", c)
	}
}
