// Package proxy adalah reverse proxy yang menjalankan pemeriksaan WAF pada
// setiap permintaan sebelum meneruskannya ke backend asli.
package proxy

import (
	"bytes"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"exactuswaf/internal/autoban"
	"exactuswaf/internal/config"
	"exactuswaf/internal/dashboard"
	"exactuswaf/internal/notify"
	"exactuswaf/internal/ratelimit"
	"exactuswaf/internal/stats"
	"exactuswaf/internal/waf"
)

// Server menyatukan reverse proxy dengan mesin WAF.
type Server struct {
	cfg       *config.Config
	plan      atomic.Pointer[waf.Plan] // plan Web ACL aktif; diganti tanpa restart
	limiter   *ratelimit.Limiter       // selalu ada; digerbangi rlEnabled
	rlEnabled atomic.Bool              // rate limit aktif? (bisa diubah dari konsol)
	banner    *autoban.Banner
	notifier  *notify.Notifier
	stats     *stats.Store
	proxy     *httputil.ReverseProxy
	// Daftar IP blok/izin; diganti tanpa restart (atomic) + sadar CIDR.
	blockIPs   atomic.Pointer[ipMatcher]
	allowIPs   atomic.Pointer[ipMatcher]
	blockMode  atomic.Bool
	trustProxy bool
	banScope   atomic.Pointer[string]
}

// ipMatcher mencocokkan IP tunggal (exact) maupun rentang CIDR.
type ipMatcher struct {
	exact map[string]bool
	cidrs []*net.IPNet
}

// newIPMatcher mem-parse daftar entri: tiap entri boleh IP tunggal ("1.2.3.4")
// atau CIDR ("10.0.0.0/8"). Entri yang tidak valid diabaikan (validasi ketat
// dilakukan di layer settings sebelum sampai sini).
func newIPMatcher(list []string) *ipMatcher {
	m := &ipMatcher{exact: make(map[string]bool)}
	for _, raw := range list {
		v := strings.TrimSpace(raw)
		if v == "" {
			continue
		}
		if strings.Contains(v, "/") {
			if _, n, err := net.ParseCIDR(v); err == nil {
				m.cidrs = append(m.cidrs, n)
			}
			continue
		}
		m.exact[v] = true
	}
	return m
}

func (m *ipMatcher) Contains(ip string) bool {
	if m == nil {
		return false
	}
	if m.exact[ip] {
		return true
	}
	if len(m.cidrs) > 0 {
		if pip := net.ParseIP(ip); pip != nil {
			for _, n := range m.cidrs {
				if n.Contains(pip) {
					return true
				}
			}
		}
	}
	return false
}

// New membuat Server WAF dengan plan Web ACL awal.
func New(cfg *config.Config, plan *waf.Plan, st *stats.Store) (*Server, error) {
	target, err := url.Parse(cfg.Backend)
	if err != nil {
		return nil, err
	}

	rp := httputil.NewSingleHostReverseProxy(target)
	origDirector := rp.Director
	rp.Director = func(r *http.Request) {
		origDirector(r)
		// Pertahankan Host asli dari klien (JANGAN ditimpa ke host backend) agar
		// name-based virtual host di belakang (nginx/apache) tetap me-route dengan
		// benar saat ExactusWAF dipasang di depan web server.
		// Browser tidak membedakan cookie per port, jadi cookie sesi dashboard
		// bisa ikut terkirim ke sini. Jangan sampai bocor ke backend.
		stripCookie(r.Header, dashboard.SessionCookie)
	}
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("[proxy] gagal menghubungi backend %s: %v", cfg.Backend, err)
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("502 Bad Gateway - ExactusWAF tidak dapat menghubungi website asli. Cek apakah backend berjalan."))
	}

	s := &Server{
		cfg:        cfg,
		stats:      st,
		proxy:      rp,
		trustProxy: cfg.TrustProxyHeaders,
	}
	s.blockIPs.Store(newIPMatcher(cfg.IPBlock))
	s.allowIPs.Store(newIPMatcher(cfg.IPAllow))
	scope := cfg.AutoBan.Scope
	s.banScope.Store(&scope)
	s.blockMode.Store(cfg.Mode == "block")
	if plan == nil {
		plan = &waf.Plan{}
	}
	s.plan.Store(plan)
	// Limiter selalu dialokasikan (dengan nilai config atau default) agar rate
	// limit bisa dinyalakan/disetel dari konsol tanpa restart; rlEnabled yang
	// menentukan aktif/tidak.
	rpm, burst := cfg.RateLimit.RequestsPerMinute, cfg.RateLimit.Burst
	if rpm <= 0 {
		rpm = 120
	}
	if burst <= 0 {
		burst = 30
	}
	s.limiter = ratelimit.New(rpm, burst)
	s.rlEnabled.Store(cfg.RateLimit.Enabled)
	s.banner = autoban.New(cfg.AutoBan.Enabled, cfg.AutoBan.MaxStrikes,
		cfg.AutoBan.WindowMinutes, cfg.AutoBan.BanMinutes)
	s.notifier = notify.New(cfg.Notify.Telegram.Enabled,
		cfg.Notify.Telegram.BotToken, cfg.Notify.Telegram.ChatID)
	if s.notifier != nil {
		s.notifier.Send("🛡️ <b>ExactusWAF aktif</b>\nMelindungi: " +
			notify.Escape(cfg.Backend) + "\nMode: " + cfg.Mode)
	}
	return s, nil
}

// SetPlan mengganti plan Web ACL aktif tanpa menghentikan server. Aman dipanggil
// dari goroutine lain (mis. saat pengguna mengganti Web ACL dari konsol).
func (s *Server) SetPlan(p *waf.Plan) {
	if p == nil {
		p = &waf.Plan{}
	}
	s.plan.Store(p)
}

// SetIPSets mengganti daftar IP blok/izin tanpa restart (dipanggil saat admin
// mengubah IP sets dari konsol). Tiap entri boleh IP tunggal atau CIDR.
func (s *Server) SetIPSets(block, allow []string) {
	s.blockIPs.Store(newIPMatcher(block))
	s.allowIPs.Store(newIPMatcher(allow))
}

// SetRateLimit menyalakan/mematikan & menyetel ulang rate limit tanpa restart.
func (s *Server) SetRateLimit(enabled bool, requestsPerMinute, burst int) {
	s.limiter.Reconfigure(requestsPerMinute, burst)
	s.rlEnabled.Store(enabled)
}

// SetAutoBan menyetel ulang auto-ban (termasuk scope) tanpa restart.
func (s *Server) SetAutoBan(enabled bool, maxStrikes, windowMinutes, banMinutes int, scope string) {
	s.banner.SetConfig(enabled, maxStrikes, windowMinutes, banMinutes)
	if scope != "ip" && scope != "ip_ua" {
		scope = "ip_ua"
	}
	s.banScope.Store(&scope)
}

// Banner mengembalikan daftar auto-ban (untuk halaman Shield di konsol).
func (s *Server) Banner() *autoban.Banner { return s.banner }

// Mode mengembalikan mode kerja WAF saat ini ("block" atau "monitor").
func (s *Server) Mode() string {
	if s.blockMode.Load() {
		return "block"
	}
	return "monitor"
}

// SetMode mengganti mode kerja WAF tanpa restart.
func (s *Server) SetMode(mode string) error {
	switch mode {
	case "block":
		s.blockMode.Store(true)
	case "monitor":
		s.blockMode.Store(false)
	default:
		return fmt.Errorf("mode harus 'block' atau 'monitor'")
	}
	return nil
}

// stripCookie membuang satu cookie dari header Cookie tanpa mengubah cookie lain.
func stripCookie(h http.Header, name string) {
	vals := h.Values("Cookie")
	var kept []string
	removed := false
	for _, v := range vals {
		for _, part := range strings.Split(v, ";") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if k, _, _ := strings.Cut(part, "="); strings.TrimSpace(k) == name {
				removed = true
				continue
			}
			kept = append(kept, part)
		}
	}
	if !removed {
		return
	}
	h.Del("Cookie")
	if len(kept) > 0 {
		h.Set("Cookie", strings.Join(kept, "; "))
	}
}

// ServeHTTP adalah handler utama untuk semua permintaan masuk.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.stats.IncRequest()
	ip := s.clientIP(r)

	// 1. IP allowlist -> lewati semua pemeriksaan.
	if s.allowIPs.Load().Contains(ip) {
		s.stats.IncAllowed()
		setForwarded(r, ip)
		s.proxy.ServeHTTP(w, r)
		return
	}

	// 2. IP blocklist -> tolak.
	if s.blockIPs.Load().Contains(ip) {
		s.deny(w, r, ip, stats.Event{
			IP: ip, Method: r.Method, Path: r.URL.Path,
			RuleID: "IP-BLOCK", RuleName: "IP in blocklist",
			Severity: "high", Action: "ip-blocked",
		}, "ip-block")
		return
	}

	// 3. Identitas yang sedang diban otomatis -> tolak (tanpa hitung strike baru).
	if s.banner.IsBanned(s.banKey(ip, r)) {
		s.deny(w, r, ip, stats.Event{
			IP: ip, Method: r.Method, Path: r.URL.Path,
			RuleID: "AUTO-BAN", RuleName: "Auto-banned (repeat attacker)",
			Severity: "high", Action: "auto-banned",
		}, "auto-ban")
		return
	}

	// 4. Rate limit.
	if s.rlEnabled.Load() && !s.limiter.Allow(ip) {
		s.registerStrike(ip, r)
		s.deny(w, r, ip, stats.Event{
			IP: ip, Method: r.Method, Path: r.URL.Path,
			RuleID: "RATE-LIMIT", RuleName: "Too many requests",
			Severity: "medium", Action: "rate-limited",
		}, "rate-limit")
		return
	}

	// 5. Inspeksi WAF (URL, header, body).
	// Hanya 512 KB pertama yang diperiksa, TAPI body asli diteruskan utuh:
	// gabungkan bagian yang sudah dibaca dengan sisa body yang belum dibaca,
	// dan JANGAN menimpa Content-Length (biar backend menerima panjang asli).
	body, err := waf.ReadBodyLimited(r)
	if err == nil && body != nil {
		if r.Body != nil {
			r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), r.Body))
		} else {
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
	}

	dec := s.plan.Load().Evaluate(r, body)
	if dec.Matched() {
		// Satu serangan = satu strike auto-ban (tak peduli berapa signature cocok).
		s.registerStrike(ip, r)
	}

	// Signature beraksi "count": selalu dicatat, tidak pernah memblokir.
	for _, m := range dec.Counts {
		s.record(r, ip, m, "counted")
		log.Printf("[COUNT] %s %s dari %s | %s (%s)", r.Method, r.URL.Path, ip, m.RuleName, m.RuleID)
	}

	// Signature beraksi "block": blokir hanya di mode block; di mode pantau dicatat.
	if dec.Block != nil {
		if s.blockMode.Load() {
			ev := event(r, ip, dec.Block, "blocked")
			s.deny(w, r, ip, ev, dec.Block.Category)
			return
		}
		s.record(r, ip, dec.Block, "monitored")
		log.Printf("[MONITOR] %s %s dari %s | %s (%s) bukti=%q",
			r.Method, r.URL.Path, ip, dec.Block.RuleName, dec.Block.RuleID, dec.Block.Evidence)
	}

	// 6. Bersih -> teruskan ke backend.
	s.stats.IncAllowed()
	setForwarded(r, ip)
	s.proxy.ServeHTTP(w, r)
}

// setForwarded memberi tahu backend IP & skema asli klien (penting saat
// ExactusWAF berdiri di depan web server). Dipanggil tepat sebelum meneruskan,
// jadi pemeriksaan WAF di atas hanya melihat header asli klien.
func setForwarded(r *http.Request, ip string) {
	// X-Forwarded-For ditangani otomatis oleh httputil.ReverseProxy (append dari
	// RemoteAddr). Kita hanya menambah X-Real-IP + skema/host.
	r.Header.Set("X-Real-IP", ip)
	proto := "http"
	if r.TLS != nil {
		proto = "https"
	}
	r.Header.Set("X-Forwarded-Proto", proto)
	if r.Header.Get("X-Forwarded-Host") == "" {
		r.Header.Set("X-Forwarded-Host", r.Host)
	}
}

// event menyusun stats.Event dari sebuah match WAF.
func event(r *http.Request, ip string, m *waf.Match, action string) stats.Event {
	return stats.Event{
		Time: time.Now(), IP: ip, Method: r.Method, Path: r.URL.Path,
		RuleID: m.RuleID, RuleName: m.RuleName, CVE: m.CVE,
		Severity: m.Severity, Action: action,
	}
}

// record mencatat satu match (count/monitor) ke statistik.
func (s *Server) record(r *http.Request, ip string, m *waf.Match, action string) {
	s.stats.RecordBlock(event(r, ip, m, action), m.Category)
}

// registerStrike mencatat pelanggaran untuk auto-ban dan mengirim notifikasi
// bila IP baru saja diblokir otomatis.
func (s *Server) registerStrike(ip string, r *http.Request) {
	if s.banner == nil {
		return
	}
	if !s.banner.Strike(s.banKey(ip, r)) {
		return
	}
	mins := s.banner.BanMinutes()
	// Catatan: permintaan pemicu ini SUDAH dihitung (blocked/counted) di ServeHTTP,
	// jadi milestone ban tidak dicatat ulang ke statistik agar tidak dobel-hitung.
	// Permintaan berikutnya dari IP yang sama akan tercatat sebagai "auto-banned".
	log.Printf("[AUTO-BAN] %s diblokir %d menit setelah serangan berulang", ip, mins)
	s.notifier.Send(fmt.Sprintf(
		"🚫 <b>IP diblokir otomatis</b>\nIP: <code>%s</code>\nDurasi: %d menit\nTerakhir: %s %s",
		notify.Escape(ip), mins, notify.Escape(r.Method), notify.Escape(r.URL.Path)))
}

func (s *Server) deny(w http.ResponseWriter, r *http.Request, ip string, ev stats.Event, category string) {
	ev.Time = time.Now()
	s.stats.RecordBlock(ev, category)
	log.Printf("[BLOCK] %s %s dari %s | %s (%s)", r.Method, r.URL.Path, ip, ev.RuleName, ev.RuleID)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Blocked-By", "ExactusWAF")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(blockPage(ev.RuleID)))
}

func blockPage(ruleID string) string {
	return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>403 Forbidden</title>
<style>html{color-scheme:light dark}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
font-family:system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
background:#fff;color:#1a1a1a}
@media (prefers-color-scheme:dark){body{background:#0f1115;color:#e6e6e6}}
.box{text-align:center;padding:24px;max-width:420px}
.code{font-size:56px;font-weight:700;letter-spacing:-1px;line-height:1;margin:0}
h1{font-size:18px;font-weight:600;margin:8px 0 10px}
p{margin:0;font-size:14px;line-height:1.5;color:#6b7280}
.ref{margin-top:20px;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;
font-size:12px;color:#9ca3af}</style></head>
<body><div class="box">
<p class="code">403</p>
<h1>Forbidden</h1>
<p>Your request was blocked for security reasons.</p>
<p class="ref">Reference ID: ` + ruleID + `</p>
</div></body></html>`
}

// clientIP mengambil IP asli klien.
//
// Header X-Forwarded-For / X-Real-IP HANYA dipercaya bila trust_proxy_headers=true,
// yaitu saat ExactusWAF benar-benar berdiri di belakang reverse proxy tepercaya
// (mis. Nginx/Cloudflare). Bila tidak, header itu diabaikan karena penyerang dapat
// memalsukannya untuk (a) menghindari ban, atau (b) sengaja memicu ban terhadap IP
// orang lain yang tak bersalah.
func (s *Server) clientIP(r *http.Request) string {
	if s.trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			return strings.TrimSpace(parts[0])
		}
		if xr := r.Header.Get("X-Real-IP"); xr != "" {
			return strings.TrimSpace(xr)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// banKey menentukan "identitas" yang diblokir auto-ban.
//
//   - scope "ip"    : kunci = IP saja (agresif; dapat menyeret pengguna lain yang
//     berbagi satu IP publik CGNAT — umum pada ISP seluler seperti Telkomsel).
//   - scope "ip_ua" : kunci = IP + sidik jari User-Agent (default). Pengguna sah
//     dengan browser normal tidak akan berbagi kunci dengan alat serangan, sehingga
//     ban jauh lebih kecil kemungkinannya menyeret orang tak bersalah di IP yang sama.
func (s *Server) banKey(ip string, r *http.Request) string {
	scope := ""
	if p := s.banScope.Load(); p != nil {
		scope = *p
	}
	if scope == "ip_ua" {
		h := fnv.New32a()
		_, _ = h.Write([]byte(r.UserAgent()))
		return ip + "|" + strconv.FormatUint(uint64(h.Sum32()), 16)
	}
	return ip
}
