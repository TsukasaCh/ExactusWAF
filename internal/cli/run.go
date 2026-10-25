// Package cli implements the exactuswaf command-line interface: running from a
// config file, and the "protect" family of commands that put ExactusWAF in
// front of a specific app (a backend URL, an nginx site, or a Docker container).
package cli

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"exactuswaf/internal/config"
	"exactuswaf/internal/dashboard"
	"exactuswaf/internal/proxy"
	"exactuswaf/internal/settings"
	"exactuswaf/internal/sites"
	"exactuswaf/internal/stats"
	"exactuswaf/internal/waf"
	"exactuswaf/internal/webacl"
)

// portNum extracts the numeric port from a "host:port" listen address (0 if none).
func portNum(addr string) int {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(p)
	return n
}

// RunServer wires the catalog, Web ACL store, proxy and console together and
// serves until the process is stopped. It blocks.
func RunServer(cfg *config.Config, appVersion string) error {
	if cfg.LogFile != "" {
		f, err := os.OpenFile(cfg.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return fmt.Errorf("tidak bisa membuka file log: %w", err)
		}
		defer f.Close()
		log.SetOutput(io.MultiWriter(os.Stdout, f))
	}
	log.SetFlags(log.LstdFlags)

	catalog, err := waf.LoadCatalog(cfg.RulesFile)
	if err != nil {
		return fmt.Errorf("gagal memuat aturan: %w", err)
	}

	var aclPath string
	if cfg.DataDir != "" {
		aclPath = filepath.Join(cfg.DataDir, "webacl.json")
	}
	acls, err := webacl.NewStore(aclPath, catalog)
	if err != nil {
		return fmt.Errorf("gagal memuat Web ACL: %w", err)
	}

	st := stats.New()
	wafServer, err := proxy.New(cfg, acls.Plan(), st)
	if err != nil {
		return fmt.Errorf("gagal menyiapkan proxy: %w", err)
	}
	acls.OnChange(wafServer.SetPlan)

	// Runtime-editable settings (rate limit, auto-ban, IP sets), persisted to
	// <data_dir>/settings.json and seeded from config.yaml on first run.
	var setPath string
	if cfg.DataDir != "" {
		setPath = filepath.Join(cfg.DataDir, "settings.json")
	}
	setStore, err := settings.NewStore(setPath, settings.Settings{
		RateLimit: settings.RateLimit{Enabled: cfg.RateLimit.Enabled, RequestsPerMinute: cfg.RateLimit.RequestsPerMinute, Burst: cfg.RateLimit.Burst},
		AutoBan: settings.AutoBan{Enabled: cfg.AutoBan.Enabled, MaxStrikes: cfg.AutoBan.MaxStrikes,
			WindowMinutes: cfg.AutoBan.WindowMinutes, BanMinutes: cfg.AutoBan.BanMinutes, Scope: cfg.AutoBan.Scope},
		Blocklist: cfg.IPBlock,
		Allowlist: cfg.IPAllow,
	})
	if err != nil {
		return fmt.Errorf("gagal memuat settings: %w", err)
	}
	// OnChange fires immediately with the persisted settings, so the proxy picks
	// them up at startup and on every later console edit — without a restart.
	setStore.OnChange(func(s settings.Settings) {
		wafServer.SetRateLimit(s.RateLimit.Enabled, s.RateLimit.RequestsPerMinute, s.RateLimit.Burst)
		wafServer.SetAutoBan(s.AutoBan.Enabled, s.AutoBan.MaxStrikes, s.AutoBan.WindowMinutes, s.AutoBan.BanMinutes, s.AutoBan.Scope)
		wafServer.SetIPSets(s.Blocklist, s.Allowlist)
	})

	// Multi-app routing: one WAF fronts many apps. The default backend
	// (config.yaml) is the catch-all; extra apps (added from the console) route
	// by Host and/or a dedicated port. Host routes apply live; new ports need a
	// restart to open the socket.
	var sitesPath string
	if cfg.DataDir != "" {
		sitesPath = filepath.Join(cfg.DataDir, "sites.json")
	}
	// Reserve ExactusWAF's own ports so an app can't claim them and crash the
	// process (its dedicated listener would collide with the WAF/console socket).
	reserved := []int{portNum(cfg.Listen)}
	if cfg.Dashboard.Enabled {
		reserved = append(reserved, portNum(cfg.Dashboard.Listen))
	}
	siteStore, err := sites.NewStore(sitesPath, reserved...)
	if err != nil {
		return fmt.Errorf("gagal memuat daftar app: %w", err)
	}
	siteStore.OnChange(func(list []sites.Site) {
		wafServer.SetRoutes(cfg.Backend, list)
	})
	if n := len(siteStore.List()); n > 0 {
		log.Printf("Apps          : %d extra app(s) protected (plus the default backend)", n)
	}

	log.Printf("Rules loaded  : %d signatures (version %s, updated %s)", catalog.Count(), catalog.Version, catalog.Updated)
	log.Printf("Active Web ACL: %s (%d signatures)", acls.Active().Name, len(acls.Active().Rules))
	log.Printf("Mode          : %s", cfg.Mode)
	log.Printf("Protecting    : %s", cfg.Backend)
	log.Printf("Listening     : http://%s", cfg.Listen)

	if cfg.Dashboard.Enabled {
		dash := dashboard.New(dashboard.Deps{
			Stats: st, Catalog: catalog, ACLs: acls, Banner: wafServer.Banner(),
			Config: cfg, Settings: setStore, Sites: siteStore, Password: cfg.Dashboard.Password, AppVersion: appVersion,
			Mode: wafServer.Mode, SetMode: wafServer.SetMode,
		})
		go func() {
			log.Printf("Console       : http://%s  (user: admin)", cfg.Dashboard.Listen)
			srv := &http.Server{Addr: cfg.Dashboard.Listen, Handler: dash.Handler(), ReadHeaderTimeout: 5 * time.Second}
			if err := srv.ListenAndServe(); err != nil {
				log.Printf("[console] stopped: %v", err)
			}
		}()
	}

	// Dedicated per-port listeners for apps that route by port (not domain).
	// Started from the persisted sites at boot; a newly added port needs a
	// restart to open here.
	for _, p := range siteStore.Ports() {
		port := p
		addr := fmt.Sprintf("0.0.0.0:%d", port)
		go func() {
			log.Printf("App listener  : http://%s (port-based app)", addr)
			ps := &http.Server{Addr: addr, Handler: wafServer.PortHandler(port), ReadHeaderTimeout: 10 * time.Second}
			if err := ps.ListenAndServe(); err != nil {
				log.Printf("[app-listener %s] stopped: %v", addr, err)
			}
		}()
	}

	srv := &http.Server{Addr: cfg.Listen, Handler: wafServer, ReadHeaderTimeout: 10 * time.Second}
	fmt.Println("\n✅ ExactusWAF ready. Press Ctrl+C to stop.")
	if cfg.TLS.Enabled {
		return srv.ListenAndServeTLS(cfg.TLS.CertFile, cfg.TLS.KeyFile)
	}
	return srv.ListenAndServe()
}
