package dashboard

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// SessionCookie adalah nama cookie sesi login dashboard. Proxy WAF membuang
// cookie ini sebelum meneruskan permintaan ke backend.
const SessionCookie = "exactuswaf_session"

const (
	adminUser    = "admin"
	sessionTTL   = 12 * time.Hour
	maxFailures  = 5                // login gagal sebanyak ini...
	failWindow   = 15 * time.Minute // ...dalam jendela waktu ini...
	lockDuration = 5 * time.Minute  // ...membuat IP itu dikunci sekian lama.
)

// sessionStore menyimpan sesi login yang aktif di memori (hilang saat restart).
type sessionStore struct {
	mu      sync.Mutex
	expires map[string]time.Time // token -> waktu kedaluwarsa
}

func newSessionStore() *sessionStore {
	s := &sessionStore{expires: make(map[string]time.Time)}
	go s.janitor()
	return s
}

// create membuat token acak baru (128 bit) yang berlaku selama sessionTTL.
func (s *sessionStore) create() string {
	token := rand.Text()
	s.mu.Lock()
	s.expires[token] = time.Now().Add(sessionTTL)
	s.mu.Unlock()
	return token
}

func (s *sessionStore) valid(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.expires[token]
	if ok && time.Now().After(exp) {
		delete(s.expires, token)
		return false
	}
	return ok
}

func (s *sessionStore) remove(token string) {
	s.mu.Lock()
	delete(s.expires, token)
	s.mu.Unlock()
}

func (s *sessionStore) janitor() {
	ticker := time.NewTicker(10 * time.Minute)
	for range ticker.C {
		now := time.Now()
		s.mu.Lock()
		for token, exp := range s.expires {
			if now.After(exp) {
				delete(s.expires, token)
			}
		}
		s.mu.Unlock()
	}
}

// loginGuard mengunci sementara IP yang terlalu sering salah login (anti brute-force).
type loginGuard struct {
	mu   sync.Mutex
	byIP map[string]*failures
}

type failures struct {
	count       int
	since       time.Time // awal jendela hitungan
	lockedUntil time.Time
}

func newLoginGuard() *loginGuard {
	g := &loginGuard{byIP: make(map[string]*failures)}
	go g.janitor()
	return g
}

// begin mencatat SATU percobaan login dan mengembalikan apakah boleh lanjut.
// Slot dipakai dan pengecekan kunci dilakukan secara atomik (dalam satu lock),
// SEBELUM kata sandi diperiksa dan sebelum body dibaca. Dengan begitu banyak
// permintaan bersamaan (termasuk body yang dikirim lambat/slowloris) tidak bisa
// melampaui kuota: percobaan ke-(maxStrikes+1) langsung dikunci.
func (g *loginGuard) begin(ip string) (allowed bool, wait time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	f, ok := g.byIP[ip]
	if !ok {
		f = &failures{since: now}
		g.byIP[ip] = f
	}
	if now.Before(f.lockedUntil) {
		return false, time.Until(f.lockedUntil)
	}
	if now.Sub(f.since) > failWindow {
		f.count, f.since = 0, now
	}
	f.count++
	if f.count > maxFailures {
		f.count, f.since, f.lockedUntil = 0, now, now.Add(lockDuration)
		return false, lockDuration
	}
	return true, 0
}

func (g *loginGuard) reset(ip string) {
	g.mu.Lock()
	delete(g.byIP, ip)
	g.mu.Unlock()
}

func (g *loginGuard) janitor() {
	ticker := time.NewTicker(10 * time.Minute)
	for range ticker.C {
		now := time.Now()
		g.mu.Lock()
		for ip, f := range g.byIP {
			if now.After(f.lockedUntil) && now.Sub(f.since) > failWindow {
				delete(g.byIP, ip)
			}
		}
		g.mu.Unlock()
	}
}

// loginView adalah data untuk template halaman login (web/login.html).
type loginView struct {
	Username string
	Error    string
	Info     string
	Version  string
}

func (d *Dashboard) renderLogin(w http.ResponseWriter, status int, v loginView) {
	v.Version = d.deps.AppVersion
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := d.loginTmpl.Execute(w, v); err != nil {
		log.Printf("[dashboard] failed to render login page: %v", err)
	}
}

func (d *Dashboard) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if d.loggedIn(r) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	var v loginView
	switch q := r.URL.Query(); {
	case q.Has("signed_out"):
		v.Info = "You have been signed out."
	case q.Has("expired"):
		v.Info = "Your session has expired. Please sign in again."
	}
	d.renderLogin(w, http.StatusOK, v)
}

// crossSiteMessage ditampilkan bila form dikirim dari luar halaman dashboard.
const crossSiteMessage = "Request rejected because it did not come from this page. Reload the page and try again."

func (d *Dashboard) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		d.renderLogin(w, http.StatusForbidden, loginView{Error: crossSiteMessage})
		return
	}
	ip := remoteIP(r)
	// Pakai slot percobaan + cek kunci secara atomik SEBELUM membaca body,
	// sehingga banyak permintaan bersamaan tidak bisa melampaui kuota.
	allowed, wait := d.guard.begin(ip)
	if !allowed {
		d.renderLogin(w, http.StatusTooManyRequests, loginView{Error: lockMessage(wait)})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if err := r.ParseForm(); err != nil {
		d.renderLogin(w, http.StatusBadRequest, loginView{Error: "Invalid request. Please try again."})
		return
	}

	user := r.PostForm.Get("username")
	if !d.checkCredentials(user, r.PostForm.Get("password")) {
		log.Printf("[dashboard] login failed from %s", ip)
		d.renderLogin(w, http.StatusUnauthorized,
			loginView{Username: user, Error: "Incorrect username or password."})
		return
	}

	d.guard.reset(ip)
	// Selalu buat token baru saat login (mencegah session fixation).
	if c, err := r.Cookie(SessionCookie); err == nil {
		d.sessions.remove(c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    d.sessions.create(),
		Path:     "/",
		MaxAge:   int(sessionTTL.Seconds()),
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
	})
	log.Printf("[dashboard] login success from %s", ip)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (d *Dashboard) handleLogout(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		d.renderLogin(w, http.StatusForbidden, loginView{Error: crossSiteMessage})
		return
	}
	if c, err := r.Cookie(SessionCookie); err == nil {
		d.sessions.remove(c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, "/login?signed_out", http.StatusSeeOther)
}

func (d *Dashboard) loggedIn(r *http.Request) bool {
	c, err := r.Cookie(SessionCookie)
	return err == nil && d.sessions.valid(c.Value)
}

// requireLogin mengarahkan ke halaman login bila belum masuk.
func (d *Dashboard) requireLogin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !d.loggedIn(r) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

// requireLoginAPI menjawab 401 JSON bila belum masuk. Sengaja tanpa header
// WWW-Authenticate agar browser tidak memunculkan pop-up login bawaannya.
func (d *Dashboard) requireLoginAPI(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !d.loggedIn(r) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"login diperlukan"}`))
			return
		}
		next(w, r)
	}
}

// checkCredentials membandingkan dalam waktu konstan. Keduanya di-hash dulu
// agar panjang password pun tidak bocor lewat perbedaan waktu.
func (d *Dashboard) checkCredentials(user, pass string) bool {
	gotU, wantU := sha256.Sum256([]byte(user)), sha256.Sum256([]byte(adminUser))
	gotP, wantP := sha256.Sum256([]byte(pass)), sha256.Sum256([]byte(d.password))
	okUser := subtle.ConstantTimeCompare(gotU[:], wantU[:]) == 1
	okPass := subtle.ConstantTimeCompare(gotP[:], wantP[:]) == 1
	return okUser && okPass && d.password != ""
}

// sameOrigin menolak form yang dikirim dari situs lain (CSRF). Browser selalu
// menyertakan header Origin pada POST; klien tanpa Origin (mis. curl) dibiarkan.
func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	return err == nil && u.Host == r.Host
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func lockMessage(wait time.Duration) string {
	return fmt.Sprintf("Too many failed attempts. Try again in %d minutes.",
		int(math.Ceil(wait.Minutes())))
}
