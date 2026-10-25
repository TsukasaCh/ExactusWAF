package sites

import (
	"path/filepath"
	"testing"
)

func TestCreateValidation(t *testing.T) {
	s, _ := NewStore("")
	// Missing backend.
	if _, err := s.Create(Site{Name: "a", Domains: []string{"a.com"}}); err == nil {
		t.Error("expected missing backend to be rejected")
	}
	// Neither domain nor port.
	if _, err := s.Create(Site{Name: "a", Backend: "http://127.0.0.1:3000"}); err == nil {
		t.Error("expected site with no domain and no port to be rejected")
	}
	// Bad domain (has scheme/port).
	if _, err := s.Create(Site{Name: "a", Backend: "http://127.0.0.1:3000", Domains: []string{"http://x:80"}}); err == nil {
		t.Error("expected bad domain to be rejected")
	}
	// Port out of range.
	if _, err := s.Create(Site{Name: "a", Backend: "http://127.0.0.1:3000", Port: 70000}); err == nil {
		t.Error("expected out-of-range port to be rejected")
	}
	// Valid: domain-only.
	a, err := s.Create(Site{Name: "shop", Backend: "http://127.0.0.1:3000/", Domains: []string{" Shop.Example.com "}})
	if err != nil {
		t.Fatalf("valid create failed: %v", err)
	}
	if a.Backend != "http://127.0.0.1:3000" || a.Domains[0] != "shop.example.com" {
		t.Fatalf("not normalized: %+v", a)
	}
}

func TestUniqueness(t *testing.T) {
	s, _ := NewStore("")
	if _, err := s.Create(Site{Name: "shop", Backend: "http://127.0.0.1:3000", Domains: []string{"shop.com"}, Port: 8081}); err != nil {
		t.Fatal(err)
	}
	// Duplicate name.
	if _, err := s.Create(Site{Name: "shop", Backend: "http://127.0.0.1:3001", Domains: []string{"blog.com"}}); err == nil {
		t.Error("duplicate name should be rejected")
	}
	// Duplicate domain.
	if _, err := s.Create(Site{Name: "blog", Backend: "http://127.0.0.1:3001", Domains: []string{"shop.com"}}); err == nil {
		t.Error("duplicate domain should be rejected")
	}
	// Duplicate port.
	if _, err := s.Create(Site{Name: "blog", Backend: "http://127.0.0.1:3001", Port: 8081}); err == nil {
		t.Error("duplicate port should be rejected")
	}
}

func TestPersistAndReloadAndPorts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sites.json")
	s, _ := NewStore(path)
	var fired int
	s.OnChange(func([]Site) { fired++ })
	a, err := s.Create(Site{Name: "api", Backend: "http://127.0.0.1:9000", Port: 8090})
	if err != nil {
		t.Fatal(err)
	}
	if fired < 2 { // once on register, once on create
		t.Fatalf("OnChange fired %d times, want >=2", fired)
	}

	s2, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := s2.Get(a.ID)
	if !ok || got.Port != 8090 {
		t.Fatalf("site not persisted: %+v ok=%v", got, ok)
	}
	if ports := s2.Ports(); len(ports) != 1 || ports[0] != 8090 {
		t.Fatalf("Ports()=%v, want [8090]", ports)
	}

	if err := s2.Delete(a.ID); err != nil {
		t.Fatal(err)
	}
	if len(s2.List()) != 0 {
		t.Fatal("site not deleted")
	}
}

func TestReservedPortRejected(t *testing.T) {
	s, _ := NewStore("", 8080, 8991)
	if _, err := s.Create(Site{Name: "a", Backend: "http://127.0.0.1:3000", Port: 8080}); err == nil {
		t.Error("expected reserved WAF port 8080 to be rejected")
	}
	if _, err := s.Create(Site{Name: "b", Backend: "http://127.0.0.1:3000", Port: 8991}); err == nil {
		t.Error("expected reserved console port 8991 to be rejected")
	}
	if _, err := s.Create(Site{Name: "c", Backend: "http://127.0.0.1:3000", Port: 8081}); err != nil {
		t.Errorf("non-reserved port should be allowed: %v", err)
	}
}

func TestWildcardDomainValidation(t *testing.T) {
	s, _ := NewStore("")
	// Leading wildcard OK.
	if _, err := s.Create(Site{Name: "w", Backend: "http://127.0.0.1:3000", Domains: []string{"*.example.com"}}); err != nil {
		t.Errorf("leading wildcard should be allowed: %v", err)
	}
	// Non-leading or multiple wildcards rejected.
	for _, bad := range []string{"ab*c.com", "*.*.com", "foo.*.com"} {
		if _, err := s.Create(Site{Name: "x" + bad, Backend: "http://127.0.0.1:3000", Domains: []string{bad}}); err == nil {
			t.Errorf("expected wildcard %q to be rejected", bad)
		}
	}
}
