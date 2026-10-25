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
