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
