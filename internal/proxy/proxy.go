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
	"time"

	"exactuswaf/internal/autoban"
	"exactuswaf/internal/config"
	"exactuswaf/internal/notify"
	"exactuswaf/internal/ratelimit"
	"exactuswaf/internal/stats"
	"exactuswaf/internal/waf"
)

// Server menyatukan reverse proxy dengan mesin WAF.
type Server struct {
	cfg       *config.Config
	rules     *waf.RuleSet
	limiter   *ratelimit.Limiter
	banner    *autoban.Banner
	notifier  *notify.Notifier
	stats     *stats.Store
	proxy     *httputil.ReverseProxy
	blockSet   map[string]bool
	allowSet   map[string]bool
	blockMode  bool
	trustProxy bool
	banScope   string
}

// New membuat Server WAF.
func New(cfg *config.Config, rules *waf.RuleSet, st *stats.Store) (*Server, error) {
	target, err := url.Parse(cfg.Backend)
	if err != nil {
		return nil, err
	}

	rp := httputil.NewSingleHostReverseProxy(target)
	// Perbaiki header Host agar backend menerima host aslinya.
	origDirector := rp.Director
	rp.Director = func(r *http.Request) {
		origDirector(r)
		r.Host = target.Host
	}
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("[proxy] gagal menghubungi backend %s: %v", cfg.Backend, err)
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("502 Bad Gateway - ExactusWAF tidak dapat menghubungi website asli. Cek apakah backend berjalan."))
	}

	s := &Server{
		cfg:       cfg,
		rules:     rules,
		stats:     st,
		proxy:     rp,
		blockSet:   toSet(cfg.IPBlock),
		allowSet:   toSet(cfg.IPAllow),
		blockMode:  cfg.Mode == "block",
		trustProxy: cfg.TrustProxyHeaders,
		banScope:   cfg.AutoBan.Scope,
	}
	if cfg.RateLimit.Enabled {
		s.limiter = ratelimit.New(cfg.RateLimit.RequestsPerMinute, cfg.RateLimit.Burst)
	}
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

func toSet(list []string) map[string]bool {
	m := make(map[string]bool, len(list))
	for _, v := range list {
		m[strings.TrimSpace(v)] = true
	}
	return m
}

// ServeHTTP adalah handler utama untuk semua permintaan masuk.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.stats.IncRequest()
	ip := s.clientIP(r)

	// 1. IP allowlist -> lewati semua pemeriksaan.
	if s.allowSet[ip] {
		s.stats.IncAllowed()
		s.proxy.ServeHTTP(w, r)
		return
	}

	// 2. IP blocklist -> tolak.
	if s.blockSet[ip] {
		s.deny(w, r, ip, stats.Event{
			IP: ip, Method: r.Method, Path: r.URL.Path,
			RuleID: "IP-BLOCK", RuleName: "IP masuk daftar blokir",
			Severity: "high", Action: "ip-blocked",
		}, "ip-block", "IP Anda diblokir")
		return
	}

	// 3. Identitas yang sedang diban otomatis -> tolak (tanpa hitung strike baru).
	if s.banner.IsBanned(s.banKey(ip, r)) {
		s.deny(w, r, ip, stats.Event{
			IP: ip, Method: r.Method, Path: r.URL.Path,
			RuleID: "AUTO-BAN", RuleName: "IP diblokir otomatis (serangan berulang)",
			Severity: "high", Action: "auto-banned",
		}, "auto-ban", "IP Anda diblokir sementara karena aktivitas mencurigakan.")
		return
	}

	// 4. Rate limit.
	if s.limiter != nil && !s.limiter.Allow(ip) {
		s.registerStrike(ip, r)
		s.deny(w, r, ip, stats.Event{
			IP: ip, Method: r.Method, Path: r.URL.Path,
			RuleID: "RATE-LIMIT", RuleName: "Terlalu banyak permintaan",
			Severity: "medium", Action: "rate-limited",
		}, "rate-limit", "Terlalu banyak permintaan. Coba lagi nanti.")
		return
	}

	// 5. Inspeksi WAF (URL, header, body).
	body, err := waf.ReadBodyLimited(r)
	if err == nil && body != nil {
		// Kembalikan body agar bisa diteruskan ke backend.
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
	}

	if match := s.rules.Inspect(r, body); match != nil {
		// Setiap serangan dihitung sebagai "strike" untuk auto-ban.
		s.registerStrike(ip, r)
		ev := stats.Event{
			Time: time.Now(), IP: ip, Method: r.Method, Path: r.URL.Path,
			RuleID: match.RuleID, RuleName: match.RuleName, CVE: match.CVE,
			Severity: match.Severity,
		}
		if s.blockMode {
			ev.Action = "blocked"
			s.deny(w, r, ip, ev, match.Category, "Permintaan diblokir oleh ExactusWAF")
			return
		}
		// Mode monitor: catat tapi teruskan.
		ev.Action = "monitored"
		s.stats.RecordBlock(ev, match.Category)
		log.Printf("[MONITOR] %s %s dari %s | %s (%s) bukti=%q",
			r.Method, r.URL.Path, ip, match.RuleName, match.CVE, match.Evidence)
	}

	// 6. Bersih -> teruskan ke backend.
	s.stats.IncAllowed()
	s.proxy.ServeHTTP(w, r)
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
	s.stats.RecordBlock(stats.Event{
		Time: time.Now(), IP: ip, Method: r.Method, Path: r.URL.Path,
		RuleID: "AUTO-BAN", RuleName: fmt.Sprintf("IP diblokir otomatis %d menit", mins),
		Severity: "high", Action: "auto-banned",
	}, "auto-ban")
	log.Printf("[AUTO-BAN] %s diblokir %d menit setelah serangan berulang", ip, mins)
	s.notifier.Send(fmt.Sprintf(
		"🚫 <b>IP diblokir otomatis</b>\nIP: <code>%s</code>\nDurasi: %d menit\nTerakhir: %s %s",
		notify.Escape(ip), mins, notify.Escape(r.Method), notify.Escape(r.URL.Path)))
}

func (s *Server) deny(w http.ResponseWriter, r *http.Request, ip string, ev stats.Event, category, reason string) {
	ev.Time = time.Now()
	s.stats.RecordBlock(ev, category)
	log.Printf("[BLOCK] %s %s dari %s | %s (%s)", r.Method, r.URL.Path, ip, ev.RuleName, ev.RuleID)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Blocked-By", "ExactusWAF")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(blockPage(reason, ev.RuleID)))
}

func blockPage(reason, ruleID string) string {
	return `<!doctype html><html lang="id"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Diblokir - ExactusWAF</title>
<style>body{font-family:system-ui,Segoe UI,sans-serif;background:#0f172a;color:#e2e8f0;
display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}
.card{background:#1e293b;padding:40px;border-radius:16px;max-width:460px;text-align:center;
box-shadow:0 20px 60px rgba(0,0,0,.4)}h1{color:#f87171;margin:0 0 8px}
.id{font-family:monospace;color:#94a3b8;font-size:13px;margin-top:16px}
.shield{font-size:48px}</style></head>
<body><div class="card"><div class="shield">🛡️</div>
<h1>Akses Diblokir</h1><p>` + reason + `</p>
<p style="color:#94a3b8;font-size:14px">Permintaan Anda terdeteksi berpotensi berbahaya dan
dihentikan oleh ExactusWAF.</p>
<div class="id">Ref: ` + ruleID + `</div></div></body></html>`
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
	if s.banScope == "ip_ua" {
		h := fnv.New32a()
		_, _ = h.Write([]byte(r.UserAgent()))
		return ip + "|" + strconv.FormatUint(uint64(h.Sum32()), 16)
	}
	return ip
}
