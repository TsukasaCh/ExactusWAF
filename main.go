// ExactusWAF - Web Application Firewall sederhana berbasis Go.
//
// Cara pakai:
//
//	exactuswaf                 -> memakai config.yaml di folder yang sama
//	exactuswaf -config lain.yaml
//	exactuswaf -version
package main

import (
	"flag"
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

const version = "2.0.0"

func main() {
	cfgPath := flag.String("config", "config.yaml", "path ke file konfigurasi")
	showVer := flag.Bool("version", false, "tampilkan versi lalu keluar")
	flag.Parse()

	if *showVer {
		fmt.Printf("ExactusWAF v%s\n", version)
		return
	}

	banner()

	// 1. Muat konfigurasi.
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fatal("Konfigurasi bermasalah", err)
	}
	for _, w := range cfg.Warnings {
		fmt.Fprintf(os.Stderr, "⚠️  %s\n", w)
	}

	// 2. Siapkan log.
	if cfg.LogFile != "" {
		f, err := os.OpenFile(cfg.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			fatal("Tidak bisa membuka file log", err)
		}
		defer f.Close()
		log.SetOutput(io.MultiWriter(os.Stdout, f))
	}
	log.SetFlags(log.LstdFlags)

	// 3. Muat katalog signature.
	catalog, err := waf.LoadCatalog(cfg.RulesFile)
	if err != nil {
		fatal("Gagal memuat aturan", err)
	}

	// 4. Web ACL (tersimpan di data_dir bila diisi).
	var aclPath string
	if cfg.DataDir != "" {
		aclPath = filepath.Join(cfg.DataDir, "webacl.json")
	}
	acls, err := webacl.NewStore(aclPath, catalog)
	if err != nil {
		fatal("Gagal memuat Web ACL", err)
	}

	// 5. Statistik + WAF server (plan awal dari Web ACL aktif).
	st := stats.New()
	wafServer, err := proxy.New(cfg, acls.Plan(), st)
	if err != nil {
		fatal("Gagal menyiapkan proxy", err)
	}
	// Setiap perubahan Web ACL aktif langsung diterapkan ke mesin WAF tanpa restart.
	acls.OnChange(wafServer.SetPlan)

	log.Printf("Aturan dimuat : %d signature (versi %s, update %s)", catalog.Count(), catalog.Version, catalog.Updated)
	log.Printf("Web ACL aktif : %s (%d signature)", acls.Active().Name, len(acls.Active().Rules))
	log.Printf("Mode          : %s", cfg.Mode)
	log.Printf("Melindungi    : %s", cfg.Backend)
	log.Printf("Mendengarkan  : http://%s", cfg.Listen)

	// 6. Jalankan konsol (jika aktif) di goroutine terpisah.
	if cfg.Dashboard.Enabled {
		dash := dashboard.New(dashboard.Deps{
			Stats: st, Catalog: catalog, ACLs: acls, Banner: wafServer.Banner(),
			Config: cfg, Password: cfg.Dashboard.Password, AppVersion: version,
			Mode: wafServer.Mode, SetMode: wafServer.SetMode,
		})
		go func() {
			log.Printf("Konsol        : http://%s  (user: admin)", cfg.Dashboard.Listen)
			srv := &http.Server{
				Addr:              cfg.Dashboard.Listen,
				Handler:           dash.Handler(),
				ReadHeaderTimeout: 5 * time.Second,
			}
			if err := srv.ListenAndServe(); err != nil {
				log.Printf("[konsol] berhenti: %v", err)
			}
		}()
	}

	// 6. Jalankan server utama WAF.
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           wafServer,
		ReadHeaderTimeout: 10 * time.Second,
	}

	fmt.Println("\n✅ ExactusWAF siap. Tekan Ctrl+C untuk berhenti.")

	if cfg.TLS.Enabled {
		err = srv.ListenAndServeTLS(cfg.TLS.CertFile, cfg.TLS.KeyFile)
	} else {
		err = srv.ListenAndServe()
	}
	if err != nil {
		fatal("Server berhenti", err)
	}
}

func banner() {
	fmt.Println(`
   ______                 __            _       _____    ____
  / ____/  ____ _ _____  / /_ __  __  (_)_____/ ___/   /  _/
 / __/    / __ ` + "`" + `// ___/ / __// / / / / // ___/\__ \    / /
/ /___   / /_/ // /__  / /_ / /_/ / / /(__  )___/ /  _/ /
\____/   \__,_/ \___/  \__/ \__,_/ /_//____//____/  /___/
                          ExactusWAF - Web Application Firewall`)
}

func fatal(msg string, err error) {
	fmt.Fprintf(os.Stderr, "\n❌ %s:\n   %v\n\nSilakan periksa config.yaml lalu jalankan lagi.\n", msg, err)
	os.Exit(1)
}
