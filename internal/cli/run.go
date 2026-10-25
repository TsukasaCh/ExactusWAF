// Package cli implements the exactuswaf command-line interface: running from a
// config file, and the "protect" family of commands that put ExactusWAF in
// front of a specific app (a backend URL, an nginx site, or a Docker container).
package cli

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"exactuswaf/internal/config"
	"exactuswaf/internal/dashboard"
	"exactuswaf/internal/proxy"
	"exactuswaf/internal/stats"
	"exactuswaf/internal/waf"
	"exactuswaf/internal/webacl"
)

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

	log.Printf("Rules loaded  : %d signatures (version %s, updated %s)", catalog.Count(), catalog.Version, catalog.Updated)
	log.Printf("Active Web ACL: %s (%d signatures)", acls.Active().Name, len(acls.Active().Rules))
	log.Printf("Mode          : %s", cfg.Mode)
	log.Printf("Protecting    : %s", cfg.Backend)
	log.Printf("Listening     : http://%s", cfg.Listen)

	if cfg.Dashboard.Enabled {
		dash := dashboard.New(dashboard.Deps{
			Stats: st, Catalog: catalog, ACLs: acls, Banner: wafServer.Banner(),
			Config: cfg, Password: cfg.Dashboard.Password, AppVersion: appVersion,
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

	srv := &http.Server{Addr: cfg.Listen, Handler: wafServer, ReadHeaderTimeout: 10 * time.Second}
	fmt.Println("\n✅ ExactusWAF ready. Press Ctrl+C to stop.")
	if cfg.TLS.Enabled {
		return srv.ListenAndServeTLS(cfg.TLS.CertFile, cfg.TLS.KeyFile)
	}
	return srv.ListenAndServe()
}
