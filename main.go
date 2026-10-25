// ExactusWAF - a simple Web Application Firewall written in Go.
//
// Run from a config file (used by the service):
//
//	exactuswaf                     -> uses config.yaml in the current directory
//	exactuswaf -config other.yaml
//	exactuswaf run -config f.yaml
//	exactuswaf -version
//
// Protect a specific app with one command:
//
//	exactuswaf protect docker <id|name>          # front a Docker container
//	exactuswaf protect /etc/nginx/sites-enabled/app   # front an nginx site
//	exactuswaf protect http://127.0.0.1:3000     # front any backend
//	exactuswaf docker <id>                        # shorthand for "protect docker"
//	exactuswaf list                               # show protected apps
//	exactuswaf unprotect <name>                   # stop protecting an app
//
// Add --foreground to run in this terminal instead of installing a service,
// and --help to a protect command for all options.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"exactuswaf/internal/cli"
	"exactuswaf/internal/config"
)

const version = "2.0.0"

func main() {
	args := os.Args[1:]
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		switch args[0] {
		case "run":
			runFromConfig(args[1:])
		case "protect":
			must(cli.Protect(args[1:], version))
		case "docker": // shorthand: exactuswaf docker <id>
			must(cli.Protect(args, version))
		case "list":
			must(cli.List())
		case "unprotect":
			must(cli.Unprotect(args[1:]))
		case "help":
			usage()
		default:
			// shorthand: exactuswaf <nginx-site-file | http://host:port | host:port>
			must(cli.Protect(args, version))
		}
		return
	}
	runFromConfig(args)
}

func runFromConfig(args []string) {
	fs := flag.NewFlagSet("exactuswaf", flag.ExitOnError)
	cfgPath := fs.String("config", "config.yaml", "path to the config file")
	showVer := fs.Bool("version", false, "print version and exit")
	_ = fs.Parse(args)

	if *showVer {
		fmt.Printf("ExactusWAF v%s\n", version)
		return
	}
	banner()
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fatal("Configuration error", err)
	}
	for _, w := range cfg.Warnings {
		fmt.Fprintf(os.Stderr, "⚠️  %s\n", w)
	}
	if err := cli.RunServer(cfg, version); err != nil {
		fatal("Server stopped", err)
	}
}

func usage() {
	fmt.Print(`ExactusWAF - Web Application Firewall

Run from config:
  exactuswaf [-config config.yaml]
  exactuswaf -version

Protect an app (Linux):
  exactuswaf protect docker <id|name>
  exactuswaf protect /etc/nginx/sites-enabled/<site>
  exactuswaf protect http://127.0.0.1:3000
  exactuswaf docker <id>                 (shorthand)
  exactuswaf list
  exactuswaf unprotect <name>

Options for protect:
  --port N            public port to listen on (default 80)
  --dash-port N       dashboard port (default 8991)
  --container-port N  container port to forward to (docker)
  --mode block|monitor (default block)
  --password P        dashboard password (default: random)
  --name N            instance name
  --foreground, -f    run here instead of installing a service
  --no-relocate       (nginx) don't edit the site; set backend yourself
`)
}

func must(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n❌ %v\n", err)
		os.Exit(1)
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
	fmt.Fprintf(os.Stderr, "\n❌ %s:\n   %v\n\nCheck your config and try again.\n", msg, err)
	os.Exit(1)
}
