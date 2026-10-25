package settings

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizeIPList(t *testing.T) {
	ok, err := normalizeIPList([]string{" 1.2.3.4 ", "10.0.0.0/8", "1.2.3.4", "", "2001:db8::/32"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// dedup drops the repeat 1.2.3.4 and blank; CIDR canonicalized.
	if len(ok) != 3 {
		t.Fatalf("got %v, want 3 unique entries", ok)
	}
	if ok[0] != "1.2.3.4" || ok[1] != "10.0.0.0/8" {
		t.Fatalf("unexpected normalization: %v", ok)
	}
	for _, bad := range []string{"not-an-ip", "10.0.0.0/999", "999.1.1.1", "1.2.3.4/"} {
		if _, err := normalizeIPList([]string{bad}); err == nil {
			t.Errorf("expected %q to be rejected", bad)
		}
	}
}

func TestValidateShield(t *testing.T) {
	if err := validateRateLimit(RateLimit{Enabled: true, RequestsPerMinute: 0, Burst: 10}); err == nil {
		t.Error("rpm 0 should be rejected when enabled")
	}
	if err := validateRateLimit(RateLimit{Enabled: false}); err != nil {
		t.Error("disabled rate limit should pass regardless")
	}
	if err := validateAutoBan(AutoBan{Enabled: true, MaxStrikes: 5, WindowMinutes: 10, BanMinutes: 60, Scope: "bogus"}); err == nil {
		t.Error("bad scope should be rejected")
	}
	if err := validateAutoBan(AutoBan{Enabled: true, MaxStrikes: 5, WindowMinutes: 10, BanMinutes: 60, Scope: "ip"}); err != nil {
		t.Errorf("valid auto-ban rejected: %v", err)
	}
}

func TestStorePersistAndReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	seed := Settings{
		RateLimit: RateLimit{Enabled: false, RequestsPerMinute: 240, Burst: 60},
		AutoBan:   AutoBan{Enabled: true, MaxStrikes: 5, WindowMinutes: 10, BanMinutes: 60, Scope: "ip_ua"},
		Blocklist: []string{"1.1.1.1"},
	}
	s, err := NewStore(path, seed)
	if err != nil {
		t.Fatal(err)
	}

	var got Settings
	s.OnChange(func(cur Settings) { got = cur })
	if !got.AutoBan.Enabled || len(got.Blocklist) != 1 {
		t.Fatalf("OnChange did not fire with current settings: %+v", got)
	}

	if _, err := s.UpdateIPSets([]string{"10.0.0.0/8", "10.0.0.0/8"}, []string{"8.8.8.8"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateShield(RateLimit{Enabled: true, RequestsPerMinute: 500, Burst: 100},
		AutoBan{Enabled: false, MaxStrikes: 3, WindowMinutes: 5, BanMinutes: 30, Scope: "ip"}); err != nil {
		t.Fatal(err)
	}

	// Reload from disk: edits must survive a restart.
	s2, err := NewStore(path, Settings{})
	if err != nil {
		t.Fatal(err)
	}
	cur := s2.Get()
	if len(cur.Blocklist) != 1 || cur.Blocklist[0] != "10.0.0.0/8" {
		t.Errorf("blocklist not persisted: %v", cur.Blocklist)
	}
	if !cur.RateLimit.Enabled || cur.RateLimit.RequestsPerMinute != 500 {
		t.Errorf("rate limit not persisted: %+v", cur.RateLimit)
	}
	if cur.AutoBan.Enabled || cur.AutoBan.Scope != "ip" {
		t.Errorf("auto-ban not persisted: %+v", cur.AutoBan)
	}
}

func TestUpdateIPSetsRejectsInvalid(t *testing.T) {
	s, _ := NewStore("", Settings{})
	if _, err := s.UpdateIPSets([]string{"garbage"}, nil); err == nil {
		t.Fatal("expected invalid blocklist entry to be rejected")
	}
	// A rejected update must not mutate state.
	if len(s.Get().Blocklist) != 0 {
		t.Fatal("state changed despite rejected update")
	}
}

func TestPersistFailureRollsBack(t *testing.T) {
	dir := t.TempDir()
	// Make the settings "directory" actually a FILE, so MkdirAll/WriteFile fail.
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(blocker, "sub", "settings.json") // parent is a file -> persist fails
	s := &Store{path: path, cur: sanitize(Settings{Blocklist: []string{"1.1.1.1"}})}
	var fired int
	s.onChange = []func(Settings){func(Settings) { fired++ }}

	if _, err := s.UpdateIPSets([]string{"2.2.2.2"}, nil); err == nil {
		t.Fatal("expected persist failure to return an error")
	}
	// State must NOT have changed (no divergence, UI won't lie), and no OnChange.
	if cur := s.Get(); len(cur.Blocklist) != 1 || cur.Blocklist[0] != "1.1.1.1" {
		t.Fatalf("state not rolled back after persist failure: %v", cur.Blocklist)
	}
	if fired != 0 {
		t.Fatalf("OnChange fired %d times on failed persist, want 0", fired)
	}
}
