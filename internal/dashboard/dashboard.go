// Package dashboard menyajikan konsol web ExactusWAF: shell SPA, aset statis,
// halaman login, dan API JSON yang dipakai konsol.
package dashboard

import (
	"embed"
	"html/template"
	"io/fs"
	"net/http"

	"exactuswaf/internal/autoban"
	"exactuswaf/internal/config"
	"exactuswaf/internal/settings"
	"exactuswaf/internal/stats"
	"exactuswaf/internal/waf"
	"exactuswaf/internal/webacl"
)

// web berisi shell konsol, halaman login, dan aset statis (CSS/JS/ikon).
//
//go:embed web
var webFS embed.FS

// Deps adalah seluruh ketergantungan yang dibutuhkan konsol.
type Deps struct {
	Stats      *stats.Store
	Catalog    *waf.Catalog
	ACLs       *webacl.Store
	Banner     *autoban.Banner
	Config     *config.Config
	Settings   *settings.Store
	Password   string
	AppVersion string

	// Mode dan SetMode disediakan oleh proxy agar mode bisa diubah dari konsol.
	Mode    func() string
	SetMode func(mode string) error
}

type Dashboard struct {
	deps      Deps
	password  string
	sessions  *sessionStore
	guard     *loginGuard
	indexHTML []byte
	loginTmpl *template.Template
	assets    http.Handler
}

func New(d Deps) *Dashboard {
	index, err := webFS.ReadFile("web/index.html")
	if err != nil {
		panic("dashboard: index.html not found: " + err.Error())
	}
	login := template.Must(template.ParseFS(webFS, "web/login.html"))
	assetFS, err := fs.Sub(webFS, "web/assets")
	if err != nil {
		panic("dashboard: assets folder not found: " + err.Error())
	}
	return &Dashboard{
		deps:      d,
		password:  d.Password,
		sessions:  newSessionStore(),
		guard:     newLoginGuard(),
		indexHTML: index,
		loginTmpl: login,
		assets:    http.StripPrefix("/assets/", http.FileServer(http.FS(assetFS))),
	}
}

// Handler mengembalikan http.Handler untuk konsol.
func (d *Dashboard) Handler() http.Handler {
	mux := http.NewServeMux()

	// Aset statis (CSS/JS/ikon) — publik, tidak butuh login.
	mux.Handle("GET /assets/", d.assets)

	// Login / logout.
	mux.HandleFunc("GET /login", d.handleLoginPage)
	mux.HandleFunc("POST /login", d.handleLogin)
	mux.HandleFunc("POST /logout", d.handleLogout)

	// API (butuh login).
	mux.HandleFunc("GET /api/meta", d.requireLoginAPI(d.handleMeta))
	mux.HandleFunc("GET /api/stats", d.requireLoginAPI(d.handleStats))
	mux.HandleFunc("GET /api/series", d.requireLoginAPI(d.handleSeries))
	mux.HandleFunc("GET /api/signatures", d.requireLoginAPI(d.handleSignatures))
	mux.HandleFunc("GET /api/webacls", d.requireLoginAPI(d.handleListACLs))
	mux.HandleFunc("POST /api/webacls", d.requireLoginAPI(d.handleCreateACL))
	mux.HandleFunc("GET /api/webacls/{id}", d.requireLoginAPI(d.handleGetACL))
	mux.HandleFunc("PUT /api/webacls/{id}", d.requireLoginAPI(d.handleUpdateACL))
	mux.HandleFunc("DELETE /api/webacls/{id}", d.requireLoginAPI(d.handleDeleteACL))
	mux.HandleFunc("POST /api/webacls/{id}/activate", d.requireLoginAPI(d.handleActivateACL))
	mux.HandleFunc("GET /api/shield", d.requireLoginAPI(d.handleShield))
	mux.HandleFunc("PUT /api/shield/settings", d.requireLoginAPI(d.handleUpdateShield))
	mux.HandleFunc("POST /api/shield/unban", d.requireLoginAPI(d.handleUnban))
	mux.HandleFunc("GET /api/ipsets", d.requireLoginAPI(d.handleIPSets))
	mux.HandleFunc("PUT /api/ipsets", d.requireLoginAPI(d.handleUpdateIPSets))
	mux.HandleFunc("GET /api/settings", d.requireLoginAPI(d.handleSettings))
	mux.HandleFunc("POST /api/mode", d.requireLoginAPI(d.handleSetMode))

	// Shell konsol untuk semua rute lain (butuh login; routing sisi klien pakai hash).
	mux.HandleFunc("GET /", d.requireLogin(d.handleIndex))

	return secureHeaders(mux)
}

// secureHeaders menambahkan CSP dan header keamanan dasar ke setiap respons.
func secureHeaders(next http.Handler) http.Handler {
	const csp = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
		"img-src 'self' data:; connect-src 'self'; font-src 'self'; form-action 'self'; " +
		"frame-ancestors 'none'; base-uri 'none'"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

func (d *Dashboard) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(d.indexHTML)
}
