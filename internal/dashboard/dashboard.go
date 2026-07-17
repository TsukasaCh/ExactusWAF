// Package dashboard menyajikan halaman pemantauan sederhana + API JSON.
package dashboard

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"

	"exactuswaf/internal/stats"
	"exactuswaf/internal/waf"
)

type Dashboard struct {
	store    *stats.Store
	rules    *waf.RuleSet
	password string
	mode     string
}

func New(store *stats.Store, rules *waf.RuleSet, password, mode string) *Dashboard {
	return &Dashboard{store: store, rules: rules, password: password, mode: mode}
}

// Handler mengembalikan http.Handler untuk dashboard.
func (d *Dashboard) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", d.auth(d.handleIndex))
	mux.HandleFunc("/api/stats", d.auth(d.handleStats))
	return mux
}

// auth adalah HTTP Basic Auth sederhana (user: admin).
func (d *Dashboard) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		okUser := subtle.ConstantTimeCompare([]byte(user), []byte("admin")) == 1
		okPass := subtle.ConstantTimeCompare([]byte(pass), []byte(d.password)) == 1
		if !ok || !okUser || !okPass {
			w.Header().Set("WWW-Authenticate", `Basic realm="ExactusWAF Dashboard"`)
			http.Error(w, "Perlu login (user: admin)", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func (d *Dashboard) handleStats(w http.ResponseWriter, r *http.Request) {
	snap := d.store.Snapshot()
	resp := struct {
		stats.Snapshot
		Mode        string `json:"mode"`
		RulesCount  int    `json:"rules_count"`
		RulesUpdate string `json:"rules_updated"`
	}{
		Snapshot:    snap,
		Mode:        d.mode,
		RulesCount:  d.rules.Count(),
		RulesUpdate: d.rules.Updated,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (d *Dashboard) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(indexHTML))
}
