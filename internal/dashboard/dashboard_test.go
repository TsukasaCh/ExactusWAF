package dashboard

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"exactuswaf/internal/config"
	"exactuswaf/internal/settings"
	"exactuswaf/internal/stats"
	"exactuswaf/internal/waf"
	"exactuswaf/internal/webacl"
)

const testPassword = "rahasia-uji"

var errInvalidMode = errors.New("mode harus 'block' atau 'monitor'")

func newTestDash(t *testing.T) *Dashboard {
	t.Helper()
	cat, err := waf.LoadCatalog("")
	if err != nil {
		t.Fatal(err)
	}
	acls, err := webacl.NewStore("", cat)
	if err != nil {
		t.Fatal(err)
	}
	setStore, err := settings.NewStore("", settings.Settings{
		RateLimit: settings.RateLimit{Enabled: true, RequestsPerMinute: 240, Burst: 60},
		AutoBan:   settings.AutoBan{Enabled: true, MaxStrikes: 5, WindowMinutes: 10, BanMinutes: 60, Scope: "ip_ua"},
	})
	if err != nil {
		t.Fatal(err)
	}
	mode := "block"
	return New(Deps{
		Stats: stats.New(), Catalog: cat, ACLs: acls, Banner: nil,
		Config:   &config.Config{Backend: "http://contoh:8080", Mode: "block", Listen: "0.0.0.0:8080"},
		Settings: setStore,
		Password: testPassword, AppVersion: "test",
		Mode: func() string { return mode },
		SetMode: func(m string) error {
			if m != "block" && m != "monitor" {
				return errInvalidMode
			}
			mode = m
			return nil
		},
	})
}

func newTestHandler(t *testing.T) http.Handler { return newTestDash(t).Handler() }

func do(h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func loginRequest(user, pass string) *http.Request {
	form := url.Values{"username": {user}, "password": {pass}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func login(t *testing.T, h http.Handler) *http.Cookie {
	t.Helper()
	rec := do(h, loginRequest("admin", testPassword))
	for _, c := range rec.Result().Cookies() {
		if c.Name == SessionCookie {
			return c
		}
	}
	t.Fatalf("login gagal memasang cookie (status %d)", rec.Code)
	return nil
}

func TestBelumLoginDiarahkanKeHalamanLogin(t *testing.T) {
	h := newTestHandler(t)
	rec := do(h, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Fatalf("GET / tanpa login: dapat %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestAPITanpaLoginTidakMemicuPopupBrowser(t *testing.T) {
	h := newTestHandler(t)
	rec := do(h, httptest.NewRequest(http.MethodGet, "/api/stats", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("dapat %d, harusnya 401", rec.Code)
	}
	if rec.Header().Get("WWW-Authenticate") != "" {
		t.Fatal("header WWW-Authenticate memunculkan pop-up login bawaan browser")
	}
}

func TestAsetStatisTanpaLogin(t *testing.T) {
	h := newTestHandler(t)
	for _, p := range []string{"/assets/app.css", "/assets/app.js", "/assets/favicon.svg"} {
		if rec := do(h, httptest.NewRequest(http.MethodGet, p, nil)); rec.Code != http.StatusOK {
			t.Fatalf("%s: dapat %d, harusnya 200", p, rec.Code)
		}
	}
}

func TestAlurLoginDanLogout(t *testing.T) {
	h := newTestHandler(t)

	page := do(h, httptest.NewRequest(http.MethodGet, "/login", nil))
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), `name="password"`) {
		t.Fatalf("GET /login: dapat %d", page.Code)
	}

	c := login(t, h)
	if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" {
		t.Fatalf("atribut cookie kurang aman: %+v", c)
	}

	dash := do(h, withCookie(httptest.NewRequest(http.MethodGet, "/", nil), c))
	if dash.Code != http.StatusOK || !strings.Contains(dash.Body.String(), "/assets/app.js") {
		t.Fatalf("GET / setelah login: dapat %d", dash.Code)
	}
	if csp := dash.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") {
		t.Fatalf("CSP tidak membatasi script ke 'self': %q", csp)
	}
	if api := do(h, withCookie(httptest.NewRequest(http.MethodGet, "/api/stats", nil), c)); api.Code != http.StatusOK {
		t.Fatalf("GET /api/stats setelah login: dapat %d", api.Code)
	}

	out := do(h, withCookie(httptest.NewRequest(http.MethodPost, "/logout", nil), c))
	if out.Code != http.StatusSeeOther || out.Header().Get("Location") != "/login?signed_out" {
		t.Fatalf("logout: dapat %d %q", out.Code, out.Header().Get("Location"))
	}
	if api := do(h, withCookie(httptest.NewRequest(http.MethodGet, "/api/stats", nil), c)); api.Code != http.StatusUnauthorized {
		t.Fatalf("sesi masih berlaku setelah logout: dapat %d", api.Code)
	}
}

func withCookie(req *http.Request, c *http.Cookie) *http.Request {
	req.AddCookie(c)
	return req
}

func TestPasswordSalahTidakMembuatSesi(t *testing.T) {
	h := newTestHandler(t)
	rec := do(h, loginRequest("admin", "salah"))
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "Incorrect username or password") {
		t.Fatalf("dapat %d", rec.Code)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == SessionCookie && c.Value != "" {
			t.Fatal("login gagal tidak boleh memasang cookie sesi")
		}
	}
}

func TestDikunciSetelahBerulangKaliGagal(t *testing.T) {
	h := newTestHandler(t)
	for i := 0; i < maxFailures; i++ {
		do(h, loginRequest("admin", "salah"))
	}
	rec := do(h, loginRequest("admin", testPassword))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("dapat %d, harusnya 429", rec.Code)
	}
}

// TestLockoutTahanBanjirBersamaan memastikan kuota percobaan tidak bisa
// dilampaui walau banyak permintaan masuk serentak (celah slowloris/konkurensi).
func TestLockoutTahanBanjirBersamaan(t *testing.T) {
	g := newLoginGuard()
	const n = 300
	var wg sync.WaitGroup
	var mu sync.Mutex
	allowed := 0
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if ok, _ := g.begin("203.0.113.9"); ok {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()
	if allowed > maxFailures {
		t.Fatalf("%d percobaan lolos dari %d serentak; kuota maxFailures=%d terlampaui", allowed, n, maxFailures)
	}
}

func TestLoginLintasSitusDanOriginNull(t *testing.T) {
	h := newTestHandler(t)
	for _, origin := range []string{"https://evil.example", "null"} {
		req := loginRequest("admin", testPassword)
		req.Header.Set("Origin", origin)
		if rec := do(h, req); rec.Code != http.StatusForbidden {
			t.Fatalf("Origin %q: dapat %d, harusnya 403", origin, rec.Code)
		}
	}
	req := loginRequest("admin", testPassword)
	req.Header.Set("Origin", "http://"+req.Host)
	if rec := do(h, req); rec.Code != http.StatusSeeOther {
		t.Fatalf("Origin sendiri: dapat %d, harusnya 303", rec.Code)
	}
}

func TestReferrerPolicySameOrigin(t *testing.T) {
	h := newTestHandler(t)
	for _, path := range []string{"/login", "/"} {
		rec := do(h, httptest.NewRequest(http.MethodGet, path, nil))
		if p := rec.Header().Get("Referrer-Policy"); p != "same-origin" {
			t.Fatalf("%s: Referrer-Policy %q, harusnya same-origin", path, p)
		}
	}
}

// TestWebACLAPI menguji alur inti konsol: buat Web ACL, aktifkan, dan plan ikut
// berganti (dicek lewat callback OnChange).
func TestWebACLAPI(t *testing.T) {
	d := newTestDash(t)
	h := d.Handler()
	c := login(t, h)

	// Daftar awal: hanya "default" yang aktif.
	var list struct {
		ActiveID string `json:"active_id"`
		ACLs     []struct {
			ID     string `json:"id"`
			Name   string `json:"name"`
			Active bool   `json:"active"`
		} `json:"acls"`
	}
	getJSON(t, h, c, "/api/webacls", &list)
	if len(list.ACLs) != 1 || !list.ACLs[0].Active {
		t.Fatalf("daftar awal tak terduga: %+v", list)
	}

	// Buat Web ACL baru berisi 1 signature count.
	sigID := firstSignature(t, h, c)
	body := `{"name":"khusus","description":"uji","rules":[{"signature_id":"` + sigID + `","action":"count"}]}`
	var created struct {
		ID    string `json:"id"`
		Rules []struct {
			SignatureID string `json:"signature_id"`
			Action      string `json:"action"`
		} `json:"rules"`
	}
	rec := postJSON(t, h, c, http.MethodPost, "/api/webacls", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: dapat %d: %s", rec.Code, rec.Body.String())
	}
	json.Unmarshal(rec.Body.Bytes(), &created)
	if len(created.Rules) != 1 || created.Rules[0].Action != "count" {
		t.Fatalf("rules tak sesuai: %+v", created.Rules)
	}

	// Aktifkan Web ACL baru; plan harus berubah jadi 1 entri.
	var planLen int
	d.deps.ACLs.OnChange(func(p *waf.Plan) { planLen = p.Len() })
	rec = postJSON(t, h, c, http.MethodPost, "/api/webacls/"+created.ID+"/activate", `{}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("activate: dapat %d: %s", rec.Code, rec.Body.String())
	}
	if planLen != 1 {
		t.Fatalf("plan harus 1 entri setelah aktivasi, dapat %d", planLen)
	}

	// Web ACL aktif tidak boleh dihapus.
	rec = postJSON(t, h, c, http.MethodDelete, "/api/webacls/"+created.ID, "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("hapus ACL aktif: dapat %d, harusnya 400", rec.Code)
	}
}

func TestSetMode(t *testing.T) {
	d := newTestDash(t)
	h := d.Handler()
	c := login(t, h)
	rec := postJSON(t, h, c, http.MethodPost, "/api/mode", `{"mode":"monitor"}`)
	if rec.Code != http.StatusOK || d.deps.Mode() != "monitor" {
		t.Fatalf("set mode: dapat %d, mode=%s", rec.Code, d.deps.Mode())
	}
	rec = postJSON(t, h, c, http.MethodPost, "/api/mode", `{"mode":"ngaco"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("mode tak valid: dapat %d, harusnya 400", rec.Code)
	}
}

// ---- helper ----

func getJSON(t *testing.T, h http.Handler, c *http.Cookie, path string, dst any) {
	t.Helper()
	rec := do(h, withCookie(httptest.NewRequest(http.MethodGet, path, nil), c))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s: dapat %d", path, rec.Code)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), dst); err != nil {
		t.Fatalf("GET %s: json rusak: %v", path, err)
	}
}

func postJSON(t *testing.T, h http.Handler, c *http.Cookie, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://"+req.Host)
	return do(h, withCookie(req, c))
}

func firstSignature(t *testing.T, h http.Handler, c *http.Cookie) string {
	t.Helper()
	var sigs struct {
		Signatures []struct {
			ID string `json:"id"`
		} `json:"signatures"`
	}
	getJSON(t, h, c, "/api/signatures", &sigs)
	if len(sigs.Signatures) == 0 {
		t.Fatal("katalog signature kosong")
	}
	return sigs.Signatures[0].ID
}

func TestUpdateShieldSettings(t *testing.T) {
	h := newTestHandler(t)
	c := login(t, h)

	// Valid update applies.
	body := `{"auto_ban":{"enabled":false,"max_strikes":3,"window_minutes":5,"ban_minutes":30,"scope":"ip"},` +
		`"rate_limit":{"enabled":true,"requests_per_minute":500,"burst":100}}`
	rec := postJSON(t, h, c, http.MethodPut, "/api/shield/settings", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT shield settings: got %d (%s)", rec.Code, rec.Body.String())
	}
	var shield struct {
		Autoban   map[string]any `json:"autoban"`
		RateLimit map[string]any `json:"rate_limit"`
	}
	getJSON(t, h, c, "/api/shield", &shield)
	if shield.Autoban["enabled"].(bool) {
		t.Error("auto-ban should be disabled after update")
	}
	if shield.RateLimit["requests_per_minute"].(float64) != 500 {
		t.Errorf("rate limit not applied: %v", shield.RateLimit)
	}

	// Invalid scope rejected.
	bad := `{"auto_ban":{"enabled":true,"max_strikes":3,"window_minutes":5,"ban_minutes":30,"scope":"nope"},` +
		`"rate_limit":{"enabled":false,"requests_per_minute":1,"burst":1}}`
	if rec := postJSON(t, h, c, http.MethodPut, "/api/shield/settings", bad); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad scope: got %d, want 400", rec.Code)
	}
}

func TestUpdateIPSets(t *testing.T) {
	h := newTestHandler(t)
	c := login(t, h)

	rec := postJSON(t, h, c, http.MethodPut, "/api/ipsets",
		`{"blocklist":["10.0.0.0/8","1.2.3.4"],"allowlist":["8.8.8.8"]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT ipsets: got %d (%s)", rec.Code, rec.Body.String())
	}
	var sets struct {
		Blocklist []string `json:"blocklist"`
		Allowlist []string `json:"allowlist"`
	}
	getJSON(t, h, c, "/api/ipsets", &sets)
	if len(sets.Blocklist) != 2 || len(sets.Allowlist) != 1 {
		t.Fatalf("ipsets not applied: %+v", sets)
	}

	// Invalid entry rejected, state unchanged.
	if rec := postJSON(t, h, c, http.MethodPut, "/api/ipsets", `{"blocklist":["garbage"],"allowlist":[]}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid IP: got %d, want 400", rec.Code)
	}
	getJSON(t, h, c, "/api/ipsets", &sets)
	if len(sets.Blocklist) != 2 {
		t.Fatalf("state changed after rejected update: %+v", sets)
	}
}
