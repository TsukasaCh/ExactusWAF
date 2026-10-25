package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"exactuswaf/internal/config"
	"exactuswaf/internal/dashboard"
	"exactuswaf/internal/sites"
	"exactuswaf/internal/stats"
	"exactuswaf/internal/waf"
	"exactuswaf/internal/webacl"
)

func TestStripCookie(t *testing.T) {
	s := dashboard.SessionCookie
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"hanya cookie sesi", []string{s + "=abc"}, nil},
		{"cookie lain tetap utuh", []string{`a=1; ` + s + `=abc; b="x y"`}, []string{`a=1; b="x y"`}},
		{"header Cookie terpisah", []string{"a=1", s + "=abc"}, []string{"a=1"}},
		{"tanpa cookie sesi tidak diubah", []string{"a=1", "b=2"}, []string{"a=1", "b=2"}},
		{"nama mirip tidak ikut dibuang", []string{s + "x=1"}, []string{s + "x=1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{"Cookie": tc.in}
			stripCookie(h, s)
			if got := h.Values("Cookie"); strings.Join(got, "|") != strings.Join(tc.want, "|") {
				t.Fatalf("dapat %q, harusnya %q", got, tc.want)
			}
		})
	}
}

// TestBodyBesarDiteruskanUtuh memastikan body > 512 KB tidak terpotong saat
// diproksikan (WAF hanya memeriksa 512 KB pertama, tapi meneruskan seluruhnya).
func TestBodyBesarDiteruskanUtuh(t *testing.T) {
	var got int
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = len(b)
	}))
	defer backend.Close()

	cat, err := waf.LoadCatalog("")
	if err != nil {
		t.Fatal(err)
	}
	store, err := webacl.NewStore("", cat)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(&config.Config{Backend: backend.URL, Mode: "block"}, store.Plan(), stats.New())
	if err != nil {
		t.Fatal(err)
	}
	const size = 700 * 1024 // > 512 KB (batas inspeksi)
	body := bytes.Repeat([]byte("A"), size)
	req := httptest.NewRequest(http.MethodPost, "/upload", bytes.NewReader(body))
	req.ContentLength = int64(size)
	srv.ServeHTTP(httptest.NewRecorder(), req)
	if got != size {
		t.Fatalf("backend menerima %d byte, harusnya %d (body terpotong)", got, size)
	}
}

// TestForwardHostDanClientIP memastikan Host asli diteruskan (agar vhost backend
// me-route benar) dan X-Forwarded-For berisi IP klien asli.
func TestForwardHostDanClientIP(t *testing.T) {
	var gotHost, gotXFF, gotProto string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		gotXFF = r.Header.Get("X-Forwarded-For")
		gotProto = r.Header.Get("X-Forwarded-Proto")
	}))
	defer backend.Close()

	cat, err := waf.LoadCatalog("")
	if err != nil {
		t.Fatal(err)
	}
	store, err := webacl.NewStore("", cat)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(&config.Config{Backend: backend.URL, Mode: "block"}, store.Plan(), stats.New())
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "shop.example.com"
	req.RemoteAddr = "203.0.113.55:40000"
	srv.ServeHTTP(httptest.NewRecorder(), req)
	if gotHost != "shop.example.com" {
		t.Fatalf("backend menerima Host %q, harusnya host asli shop.example.com", gotHost)
	}
	if gotXFF != "203.0.113.55" {
		t.Fatalf("X-Forwarded-For %q, harusnya 203.0.113.55", gotXFF)
	}
	if gotProto != "http" {
		t.Fatalf("X-Forwarded-Proto %q, harusnya http", gotProto)
	}
}

func TestCookieSesiDashboardTidakSampaiKeBackend(t *testing.T) {
	var got string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Cookie")
	}))
	defer backend.Close()

	cat, err := waf.LoadCatalog("")
	if err != nil {
		t.Fatal(err)
	}
	store, err := webacl.NewStore("", cat)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(&config.Config{Backend: backend.URL, Mode: "block"}, store.Plan(), stats.New())
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Cookie", "app=1; "+dashboard.SessionCookie+"=rahasia")
	srv.ServeHTTP(httptest.NewRecorder(), req)
	if got != "app=1" {
		t.Fatalf("backend menerima Cookie %q, harusnya %q", got, "app=1")
	}
}

// newTestSrv builds a WAF server fronting backend with an empty Web ACL.
func newTestSrv(t *testing.T, backendURL string) *Server {
	t.Helper()
	cat, err := waf.LoadCatalog("")
	if err != nil {
		t.Fatal(err)
	}
	store, err := webacl.NewStore("", cat)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(&config.Config{Backend: backendURL, Mode: "block"}, store.Plan(), stats.New())
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

func reqFrom(ip string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = ip + ":40000"
	return req
}

func TestIPSetsCIDRAndAllowlist(t *testing.T) {
	var reached bool
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true }))
	defer backend.Close()
	srv := newTestSrv(t, backend.URL)

	// Block a whole /24, but allow one exact IP inside it.
	srv.SetIPSets([]string{"192.0.2.0/24"}, []string{"192.0.2.50"})

	// Inside the CIDR -> blocked.
	reached = false
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, reqFrom("192.0.2.10"))
	if rec.Code != http.StatusForbidden || rec.Header().Get("X-Blocked-By") != "ExactusWAF" {
		t.Fatalf("CIDR member: code=%d blockedBy=%q, want 403/ExactusWAF", rec.Code, rec.Header().Get("X-Blocked-By"))
	}
	if reached {
		t.Fatal("blocked request reached backend")
	}

	// Allowlisted exact IP inside the blocked CIDR -> allowed (allow wins).
	reached = false
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, reqFrom("192.0.2.50"))
	if !reached {
		t.Fatalf("allowlisted IP did not reach backend (code=%d)", rec.Code)
	}

	// Outside the CIDR -> allowed.
	reached = false
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, reqFrom("198.51.100.1"))
	if !reached {
		t.Fatalf("unrelated IP did not reach backend (code=%d)", rec.Code)
	}
}

func TestRateLimitLiveToggle(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer backend.Close()
	srv := newTestSrv(t, backend.URL)

	// Enable a very tight limit: 1 rpm, burst 1 -> second immediate request blocked.
	srv.SetRateLimit(true, 1, 1)
	r1 := httptest.NewRecorder()
	srv.ServeHTTP(r1, reqFrom("203.0.113.9"))
	r2 := httptest.NewRecorder()
	srv.ServeHTTP(r2, reqFrom("203.0.113.9"))
	if r1.Code == http.StatusForbidden {
		t.Fatalf("first request should pass, got %d", r1.Code)
	}
	if r2.Code != http.StatusForbidden {
		t.Fatalf("second request should be rate-limited, got %d", r2.Code)
	}

	// Disable -> requests pass again (new IP to avoid an empty bucket edge case).
	srv.SetRateLimit(false, 1, 1)
	r3 := httptest.NewRecorder()
	srv.ServeHTTP(r3, reqFrom("203.0.113.77"))
	r4 := httptest.NewRecorder()
	srv.ServeHTTP(r4, reqFrom("203.0.113.77"))
	if r3.Code == http.StatusForbidden || r4.Code == http.StatusForbidden {
		t.Fatalf("rate limit disabled but requests blocked: %d,%d", r3.Code, r4.Code)
	}
}

func TestHostAndPortRouting(t *testing.T) {
	backendA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("A")) }))
	defer backendA.Close()
	backendB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("B")) }))
	defer backendB.Close()
	backendC := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("C")) }))
	defer backendC.Close()

	srv := newTestSrv(t, backendA.URL) // default backend = A
	srv.SetRoutes(backendA.URL, []sites.Site{
		{Name: "b", Domains: []string{"b.example.com"}, Backend: backendB.URL},
		{Name: "c", Port: 8321, Backend: backendC.URL},
	})

	get := func(host string, port int) string {
		req := reqFrom("198.51.100.5")
		req.Host = host
		rec := httptest.NewRecorder()
		srv.serve(rec, req, port)
		return rec.Body.String()
	}
	if b := get("b.example.com", 0); b != "B" {
		t.Fatalf("host b.example.com routed to %q, want B", b)
	}
	if b := get("unknown.example.com", 0); b != "A" {
		t.Fatalf("unknown host routed to %q, want default A", b)
	}
	if b := get("b.example.com:80", 0); b != "B" {
		t.Fatalf("host with :port routed to %q, want B", b)
	}
	// Port listener: regardless of Host, port 8321 routes to C.
	if b := get("b.example.com", 8321); b != "C" {
		t.Fatalf("port 8321 routed to %q, want C", b)
	}
}

func TestWildcardRoutingAndPortRemoval(t *testing.T) {
	beA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("A")) }))
	defer beA.Close()
	beB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("B")) }))
	defer beB.Close()
	beC := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("C")) }))
	defer beC.Close()
	srv := newTestSrv(t, beA.URL)
	srv.SetRoutes(beA.URL, []sites.Site{
		{Name: "wild", Domains: []string{"*.example.com"}, Backend: beB.URL},
		{Name: "portapp", Port: 8321, Backend: beC.URL},
	})
	get := func(host string, port int) (int, string) {
		req := reqFrom("198.51.100.9")
		req.Host = host
		rec := httptest.NewRecorder()
		srv.serve(rec, req, port)
		return rec.Code, rec.Body.String()
	}
	if _, b := get("api.example.com", 0); b != "B" {
		t.Fatalf("subdomain wildcard routed to %q, want B", b)
	}
	if _, b := get("example.com", 0); b != "A" {
		t.Fatalf("bare domain should NOT match *.example.com, got %q want default A", b)
	}
	if _, b := get("x.local", 8321); b != "C" {
		t.Fatalf("port 8321 routed to %q, want C", b)
	}
	// Remove all sites; the still-open port listener must now refuse (502), not
	// leak the default backend.
	srv.SetRoutes(beA.URL, nil)
	if code, body := get("x.local", 8321); code != http.StatusBadGateway {
		t.Fatalf("removed port app: got %d %q, want 502", code, body)
	}
}

func TestIPv6CanonicalBlock(t *testing.T) {
	be := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer be.Close()
	srv := newTestSrv(t, be.URL)
	srv.SetIPSets([]string{"2001:db8::1"}, nil) // stored canonical lowercase
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "[2001:DB8::1]:40000" // non-canonical uppercase form
	rec := httptest.NewRecorder()
	srv.serve(rec, req, 0)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-canonical IPv6 not blocked: got %d, want 403", rec.Code)
	}
}

func TestClientIPUsesRightmostXFF(t *testing.T) {
	cat, _ := waf.LoadCatalog("")
	store, _ := webacl.NewStore("", cat)
	srv, err := New(&config.Config{Backend: "http://127.0.0.1:1", Mode: "block", TrustProxyHeaders: true}, store.Plan(), stats.New())
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// Attacker spoofs 5.5.5.5 at the left; the trusted proxy appends the real peer.
	req.Header.Set("X-Forwarded-For", "5.5.5.5, 203.0.113.9")
	req.RemoteAddr = "10.0.0.1:1234"
	if ip := srv.clientIP(req); ip != "203.0.113.9" {
		t.Fatalf("clientIP = %q, want rightmost 203.0.113.9 (spoof-resistant)", ip)
	}
}
