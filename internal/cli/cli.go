package cli

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"exactuswaf/internal/config"
)

const (
	etcDir   = "/etc/exactuswaf"
	sitesDir = "/etc/exactuswaf/sites"
	dataRoot = "/var/lib/exactuswaf"
	logRoot  = "/var/log/exactuswaf"
	unitDir  = "/etc/systemd/system"
)

// opts holds parsed `protect` options.
type opts struct {
	port       int    // public port ExactusWAF listens on
	dashPort   int    // dashboard port
	cPort      int    // docker container port override
	mode       string // block|monitor
	password   string
	name       string
	foreground bool
	noRelocate bool
}

// Protect handles: exactuswaf protect <target> [flags]
//
//	target forms: docker <id|name> | <nginx-site-file> | http://host:port | host:port | port
func Protect(args []string, appVersion string) error {
	o := opts{mode: "block"}
	var pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch a {
		case "--port":
			o.port = atoiArg(args, &i)
		case "--dash-port", "--dashboard-port":
			o.dashPort = atoiArg(args, &i)
		case "--container-port":
			o.cPort = atoiArg(args, &i)
		case "--mode":
			i++
			o.mode = argAt(args, i)
		case "--password":
			i++
			o.password = argAt(args, i)
		case "--name":
			i++
			o.name = argAt(args, i)
		case "-f", "--foreground":
			o.foreground = true
		case "--no-relocate":
			o.noRelocate = true
		default:
			pos = append(pos, a)
		}
	}
	if len(pos) == 0 {
		return fmt.Errorf("usage: exactuswaf protect <docker ID | nginx-site-file | http://host:port | host:port>")
	}
	if o.mode != "block" && o.mode != "monitor" {
		return fmt.Errorf("--mode must be block or monitor")
	}

	var backend, name string
	publicPort := o.port
	var relocateNote string

	switch {
	case pos[0] == "docker":
		if len(pos) < 2 {
			return fmt.Errorf("usage: exactuswaf protect docker <container ID or name>")
		}
		b, cname, pubPorts, hostPorts, err := resolveDocker(pos[1], o.cPort)
		if err != nil {
			return err
		}
		backend, name = b, cname
		// Front the port users actually reach: the container's published host
		// port. If the user didn't override --port and the container publishes
		// one, take it over (otherwise traffic to that port skips the WAF).
		if publicPort == 0 {
			switch {
			case len(pubPorts) > 0:
				publicPort = pubPorts[0]
			case len(hostPorts) > 0:
				publicPort = hostPorts[0]
			default:
				publicPort = 80
			}
		}
		// The WAF reaches the container over the Docker network, so the container
		// must NOT publish the WAF's port to the host (any interface) — otherwise
		// the WAF can't bind it. Detect that and explain the fix.
		if !portFree(publicPort) {
			if contains(hostPorts, publicPort) {
				return dockerBypassError(cname, publicPort)
			}
			return fmt.Errorf("port %d is already in use by another service; choose a different --port", publicPort)
		}
	case isExistingFile(pos[0]):
		if runtime.GOOS != "linux" {
			return fmt.Errorf("protecting an nginx site is only supported on Linux")
		}
		b, pub, note, err := protectNginxSite(pos[0], publicPort, o.noRelocate)
		if err != nil {
			return err
		}
		backend, publicPort, relocateNote = b, pub, note
		name = sanitizeName(strings.TrimSuffix(filepath.Base(pos[0]), filepath.Ext(pos[0])))
	default:
		b, err := normalizeBackend(pos[0])
		if err != nil {
			return err
		}
		backend = b
		if publicPort == 0 {
			publicPort = 80
		}
		name = hostFromBackend(b)
	}

	if o.name != "" {
		name = sanitizeName(o.name)
	}
	if name == "" {
		name = "app"
	}

	dashPort := o.dashPort
	if dashPort == 0 {
		dashPort = firstFreePort(8991)
	}
	pass := o.password
	if pass == "" {
		pass = randomPassword()
	}

	cfg := &config.Config{
		Listen:            fmt.Sprintf("0.0.0.0:%d", publicPort),
		Backend:           backend,
		Mode:              o.mode,
		Dashboard:         config.DashboardConfig{Enabled: true, Listen: fmt.Sprintf("0.0.0.0:%d", dashPort), Password: pass},
		RateLimit:         config.RateLimitConfig{Enabled: true, RequestsPerMinute: 240, Burst: 60},
		AutoBan:           config.AutoBanConfig{Enabled: true, MaxStrikes: 5, WindowMinutes: 10, BanMinutes: 60, Scope: "ip_ua"},
		TrustProxyHeaders: false,
	}

	if o.foreground {
		fmt.Printf("Protecting %s  ->  listening on :%d, console on :%d (admin / %s)\n", backend, publicPort, dashPort, pass)
		if relocateNote != "" {
			fmt.Println(relocateNote)
		}
		return RunServer(cfg, appVersion)
	}

	// Install as a persistent systemd service.
	if runtime.GOOS != "linux" {
		return fmt.Errorf("installing a service needs Linux; use --foreground to run here")
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("run as root to install a service (or add --foreground to run in this terminal)")
	}
	cfg.LogFile = filepath.Join(logRoot, name+".log")
	cfg.DataDir = filepath.Join(dataRoot, name)
	if err := installService(name, cfg); err != nil {
		return err
	}
	host := dashboardHost()
	fmt.Println("-------------------------------------------------------------")
	fmt.Printf("  Protected      : %s  (via ExactusWAF on port %d)\n", backend, publicPort)
	fmt.Printf("  Dashboard      : http://%s:%d   (admin / %s)\n", host, dashPort, pass)
	fmt.Printf("  Service        : exactuswaf-%s  (systemctl status exactuswaf-%s)\n", name, name)
	fmt.Println("-------------------------------------------------------------")
	fmt.Printf("Open the dashboard port in your firewall if needed:  ufw allow %d/tcp\n", dashPort)
	if relocateNote != "" {
		fmt.Println(relocateNote)
	}
	fmt.Printf("Stop protecting: exactuswaf unprotect %s\n", name)
	return nil
}

// protectNginxSite relocates the site's public HTTP listen to an internal port so
// ExactusWAF can take the original port. Returns backend URL, public port, a note.
func protectNginxSite(path string, wantPort int, noRelocate bool) (backend string, publicPort int, note string, err error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", 0, "", err
	}
	ports := parseNginxListenPorts(string(raw))
	if len(ports) == 0 {
		return "", 0, "", fmt.Errorf("no 'listen' directive found in %s", path)
	}
	publicPort = wantPort
	if publicPort == 0 {
		publicPort, err = pickPublicHTTPPort(ports)
		if err != nil {
			return "", 0, "", err
		}
	}
	internal := firstFreePort(8080)
	backend = fmt.Sprintf("http://127.0.0.1:%d", internal)
	if noRelocate {
		return backend, publicPort, fmt.Sprintf("NOTE: --no-relocate set; point nginx's :%d site to %s yourself.", publicPort, backend), nil
	}
	bak := path + ".exactuswaf.bak"
	if _, statErr := os.Stat(bak); statErr != nil {
		_ = os.WriteFile(bak, raw, 0o644)
	}
	reV6 := regexp.MustCompile(fmt.Sprintf(`listen(\s+)\[::\]:%d\b`, publicPort))
	reV4 := regexp.MustCompile(fmt.Sprintf(`listen(\s+)(\*:)?%d\b`, publicPort))
	out := reV6.ReplaceAllString(string(raw), fmt.Sprintf("listen${1}[::1]:%d", internal))
	out = reV4.ReplaceAllString(out, fmt.Sprintf("listen${1}127.0.0.1:%d", internal))
	if err := os.WriteFile(path, []byte(out), 0o644); err != nil {
		return "", 0, "", err
	}
	if err := exec.Command("nginx", "-t").Run(); err != nil {
		_ = os.WriteFile(path, raw, 0o644) // rollback
		return "", 0, "", fmt.Errorf("nginx config test failed after edit; reverted %s", path)
	}
	if err := exec.Command("systemctl", "reload", "nginx").Run(); err != nil {
		_ = exec.Command("nginx", "-s", "reload").Run()
	}
	return backend, publicPort, fmt.Sprintf("nginx site moved to %s (backup: %s); ExactusWAF now fronts port %d.", backend, bak, publicPort), nil
}

func installService(name string, cfg *config.Config) error {
	for _, d := range []string{etcDir, sitesDir, cfg.DataDir, logRoot} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	self, err := os.Executable()
	if err != nil {
		self = "/usr/local/bin/exactuswaf"
	}
	sitePath := filepath.Join(sitesDir, name+".yaml")
	if err := writeConfigYAML(sitePath, cfg); err != nil {
		return err
	}
	unit := fmt.Sprintf(`[Unit]
Description=ExactusWAF - protecting %s
After=network.target docker.service nginx.service
Wants=network.target

[Service]
Type=simple
ExecStart=%s run -config %s
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
`, cfg.Backend, self, sitePath)
	unitPath := filepath.Join(unitDir, "exactuswaf-"+name+".service")
	if err := os.WriteFile(unitPath, []byte(unit), 0o644); err != nil {
		return err
	}
	_ = exec.Command("systemctl", "daemon-reload").Run()
	if err := exec.Command("systemctl", "enable", "--now", "exactuswaf-"+name).Run(); err != nil {
		return fmt.Errorf("failed to enable service exactuswaf-%s: %w", name, err)
	}
	// systemctl returns before a Type=simple unit may crash (e.g. a port bind
	// failure), so verify it actually stayed up and surface the real reason.
	time.Sleep(1200 * time.Millisecond)
	if strings.TrimSpace(runOut("systemctl", "is-active", "exactuswaf-"+name)) != "active" {
		reason := strings.TrimSpace(runOut("journalctl", "-u", "exactuswaf-"+name, "-n", "6", "--no-pager", "-o", "cat"))
		_ = exec.Command("systemctl", "disable", "--now", "exactuswaf-"+name).Run()
		_ = os.Remove(unitPath)
		_ = os.Remove(sitePath)
		_ = exec.Command("systemctl", "daemon-reload").Run()
		hint := ""
		if strings.Contains(reason, "address already in use") {
			hint = fmt.Sprintf("\nPort %s is already taken (another service — maybe a global ExactusWAF install). Use a different --port, or stop the other one.", portOf(cfg.Listen))
		}
		return fmt.Errorf("service exactuswaf-%s did not start:\n%s%s", name, reason, hint)
	}
	return nil
}

func portOf(listen string) string {
	if i := strings.LastIndex(listen, ":"); i >= 0 {
		return listen[i+1:]
	}
	return listen
}

// List shows all protected apps and their service status.
func List() error {
	entries, _ := os.ReadDir(sitesDir)
	if len(entries) == 0 {
		fmt.Println("No apps are being protected yet. Try: exactuswaf protect docker <id>")
		return nil
	}
	fmt.Printf("%-20s %-28s %-14s %s\n", "NAME", "BACKEND", "LISTEN", "STATUS")
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".yaml")
		c, err := config.Load(filepath.Join(sitesDir, e.Name()))
		backend, listen := "?", "?"
		if err == nil {
			backend, listen = c.Backend, c.Listen
		}
		status := strings.TrimSpace(runOut("systemctl", "is-active", "exactuswaf-"+name))
		if status == "" {
			status = "unknown"
		}
		fmt.Printf("%-20s %-28s %-14s %s\n", name, backend, listen, status)
	}
	return nil
}

// Unprotect stops and removes a protected app's service.
func Unprotect(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: exactuswaf unprotect <name>  (see: exactuswaf list)")
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("run as root")
	}
	name := sanitizeName(args[0])
	_ = exec.Command("systemctl", "disable", "--now", "exactuswaf-"+name).Run()
	_ = os.Remove(filepath.Join(unitDir, "exactuswaf-"+name+".service"))
	_ = exec.Command("systemctl", "daemon-reload").Run()
	_ = os.Remove(filepath.Join(sitesDir, name+".yaml"))
	fmt.Printf("Stopped protecting %q. (Data kept in %s/%s; nginx backups end in .exactuswaf.bak)\n", name, dataRoot, name)
	return nil
}

// ---- helpers ----

func writeConfigYAML(path string, c *config.Config) error {
	// Hand-written YAML keeps it readable and avoids leaking zero-value sections.
	y := fmt.Sprintf(`# ExactusWAF site config (managed by "exactuswaf protect"; safe to edit).
listen: "%s"
backend: "%s"
mode: "%s"
dashboard:
  enabled: true
  listen: "%s"
  password: "%s"
rate_limit:
  enabled: true
  requests_per_minute: %d
  burst: %d
auto_ban:
  enabled: true
  max_strikes: %d
  window_minutes: %d
  ban_minutes: %d
  scope: "%s"
trust_proxy_headers: false
data_dir: "%s"
log_file: "%s"
`, c.Listen, c.Backend, c.Mode, c.Dashboard.Listen, c.Dashboard.Password,
		c.RateLimit.RequestsPerMinute, c.RateLimit.Burst,
		c.AutoBan.MaxStrikes, c.AutoBan.WindowMinutes, c.AutoBan.BanMinutes, c.AutoBan.Scope,
		c.DataDir, c.LogFile)
	return os.WriteFile(path, []byte(y), 0o640)
}

func isExistingFile(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func portFree(port int) bool {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}

func firstFreePort(start int) int {
	for p := start; p < start+200; p++ {
		if portFree(p) {
			return p
		}
	}
	return start
}

func randomPassword() string {
	b := make([]byte, 15)
	_, _ = rand.Read(b)
	s := base64.RawURLEncoding.EncodeToString(b)
	if len(s) > 20 {
		s = s[:20]
	}
	return s
}

var reName = regexp.MustCompile(`[^a-zA-Z0-9_.-]+`)

func sanitizeName(s string) string {
	s = reName.ReplaceAllString(strings.TrimSpace(s), "-")
	return strings.Trim(s, "-.")
}

func hostFromBackend(b string) string {
	s := strings.TrimPrefix(strings.TrimPrefix(b, "http://"), "https://")
	if i := strings.IndexAny(s, ":/"); i >= 0 {
		s = s[:i]
	}
	return sanitizeName(s)
}

func atoiArg(args []string, i *int) int {
	*i++
	n, _ := strconv.Atoi(argAt(args, *i))
	return n
}
func argAt(args []string, i int) string {
	if i >= 0 && i < len(args) {
		return args[i]
	}
	return ""
}
func contains(xs []int, v int) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

// dockerBypassError explains that the container publishes the port the WAF needs,
// and how to fix it. ExactusWAF reaches the container over the Docker network, so
// the container should not publish the port to the host at all.
func dockerBypassError(name string, port int) error {
	return fmt.Errorf(`container %q publishes port %d to the host, which ExactusWAF needs to bind.
ExactusWAF reaches your container directly over the Docker network, so the
container does NOT need to publish the port to the host. Remove the publish, then
re-protect:

  • docker compose:  replace    ports: ["...:%d:%d"]    with    expose: ["%d"]
                     then:  docker compose up -d
  • docker run:      recreate without -p (optionally add  --expose %d )
  then:              exactuswaf protect docker %s --port %d

(Only ExactusWAF should listen on port %d; it forwards clean traffic to the container.)`,
		name, port, port, port, port, port, name, port, port)
}

func runOut(name string, a ...string) string {
	out, _ := exec.Command(name, a...).Output()
	return string(out)
}

// localIP returns the host's primary outbound IP (may be a private/NAT address).
func localIP() string {
	conn, err := net.Dial("udp", "1.1.1.1:80")
	if err != nil {
		return ""
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}

// isPrivateIP reports whether the address is not reachable from the internet
// (RFC1918, loopback, link-local, or CGNAT 100.64.0.0/10).
func isPrivateIP(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return true
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return true
	}
	if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
		return true // 100.64.0.0/10 CGNAT
	}
	return false
}

// publicIP tries to discover the server's public IP (best-effort, short timeout).
func publicIP() string {
	client := &http.Client{Timeout: 2 * time.Second}
	for _, u := range []string{"https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"} {
		resp, err := client.Get(u)
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
		resp.Body.Close()
		if ip := net.ParseIP(strings.TrimSpace(string(b))); ip != nil {
			return ip.String()
		}
	}
	return ""
}

// dashboardHost returns the best host to show in the dashboard URL: the public
// IP when the local one is private/NAT, otherwise the local IP.
func dashboardHost() string {
	local := localIP()
	if local != "" && !isPrivateIP(local) {
		return local
	}
	if pub := publicIP(); pub != "" {
		return pub
	}
	if local != "" {
		return local
	}
	return "<server-ip>"
}
