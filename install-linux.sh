#!/usr/bin/env bash
# =====================================================================
#  ExactusWAF - auto installer for Ubuntu / Debian
#
#  Puts ExactusWAF in FRONT of your existing web server (nginx or
#  apache2): the web server is moved to an internal port and ExactusWAF
#  takes over the public HTTP port, inspecting every request before it
#  reaches your site. Runs as a systemd service. Dashboard on port 8991.
#
#  Usage (run as root, from inside the ExactusWAF source directory):
#     sudo bash install-linux.sh
#
#  Options:
#     --dash-port N     dashboard port            (default 8991)
#     --waf-port N      public port ExactusWAF listens on (default 80)
#     --backend URL     backend to protect when no web server is detected
#                       (e.g. http://127.0.0.1:3000)
#     --mode block|monitor   start mode           (default block)
#     --no-webserver    don't touch nginx/apache; just use --backend
#     --uninstall       remove ExactusWAF and restore web server config
#     -h | --help
# =====================================================================
set -euo pipefail

# ---- defaults ----
DASH_PORT=8991
WAF_PORT=80
BACKEND_PORT=8080          # where the local web server gets relocated to
BACKEND_URL=""             # set when --backend given or after relocation
MODE="block"
TOUCH_WS=1
ACTION="install"

BIN=/usr/local/bin/exactuswaf
ETC=/etc/exactuswaf
DATA=/var/lib/exactuswaf
LOGDIR=/var/log/exactuswaf
SVC=/etc/systemd/system/exactuswaf.service
SVCUSER=exactuswaf
BACKUP="$ETC/backup"

C_G='\033[0;32m'; C_Y='\033[1;33m'; C_R='\033[0;31m'; C_B='\033[1;34m'; C_0='\033[0m'
log()  { printf "${C_G}==>${C_0} %s\n" "$*"; }
info() { printf "    %s\n" "$*"; }
warn() { printf "${C_Y}[!]${C_0} %s\n" "$*"; }
die()  { printf "${C_R}[x] %s${C_0}\n" "$*" >&2; exit 1; }

# ---- args ----
while [ $# -gt 0 ]; do
  case "$1" in
    --dash-port) DASH_PORT="$2"; shift 2;;
    --waf-port)  WAF_PORT="$2"; shift 2;;
    --backend)   BACKEND_URL="$2"; shift 2;;
    --mode)      MODE="$2"; shift 2;;
    --no-webserver) TOUCH_WS=0; shift;;
    --uninstall) ACTION="uninstall"; shift;;
    -h|--help) grep '^#' "$0" | sed 's/^#//'; exit 0;;
    *) die "unknown option: $1 (try --help)";;
  esac
done

[ "$(id -u)" = "0" ] || die "please run as root (sudo bash install-linux.sh)"
command -v apt-get >/dev/null 2>&1 || die "this installer supports Debian/Ubuntu (apt) only"
case "$MODE" in block|monitor) ;; *) die "--mode must be block or monitor";; esac

# ---- arch for Go download ----
arch_go() {
  case "$(uname -m)" in
    x86_64|amd64) echo amd64;;
    aarch64|arm64) echo arm64;;
    armv7l) echo armv6l;;
    *) echo "";;
  esac
}

ensure_go() {
  # Returns the `go` binary to use on stdout (as GOBIN var), building needs >=1.21
  local gover have_major have_minor
  if command -v go >/dev/null 2>&1; then
    gover="$(go version | awk '{print $3}' | sed 's/go//')"
    have_major="${gover%%.*}"; have_minor="$(echo "$gover" | cut -d. -f2)"
    if [ "${have_major:-0}" -gt 1 ] || { [ "${have_major:-0}" -eq 1 ] && [ "${have_minor:-0}" -ge 21 ]; }; then
      GO=go; return
    fi
    warn "system Go $gover is too old (need >= 1.21); downloading a newer Go for the build"
  else
    log "Go not found; downloading it for the build"
  fi
  local a; a="$(arch_go)"; [ -n "$a" ] || die "unsupported CPU arch $(uname -m) for Go download"
  command -v curl >/dev/null 2>&1 || { apt-get update -qq && apt-get install -y -qq curl; }
  local ver; ver="$(curl -fsSL https://go.dev/VERSION?m=text | head -n1)"
  [ -n "$ver" ] || die "could not determine latest Go version"
  GOTMP="$(mktemp -d)"
  log "fetching ${ver} (${a})"
  curl -fsSL "https://go.dev/dl/${ver}.linux-${a}.tar.gz" | tar -C "$GOTMP" -xz
  GO="$GOTMP/go/bin/go"
  [ -x "$GO" ] || die "Go download failed"
}

build_binary() {
  [ -f go.mod ] && [ -f main.go ] || die "run this script from the ExactusWAF source directory (go.mod/main.go not found)"
  ensure_go
  log "building ExactusWAF binary (this bundles rules + console, no external files needed)"
  CGO_ENABLED=0 GOTOOLCHAIN=auto GOFLAGS=-trimpath "$GO" build -ldflags="-s -w" -o "$BIN" . \
    || die "build failed"
  [ -n "${GOTMP:-}" ] && rm -rf "$GOTMP" || true
  chmod 0755 "$BIN"
  info "installed $("$BIN" -version 2>/dev/null || echo exactuswaf) -> $BIN"
}

make_user_dirs() {
  id "$SVCUSER" >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin "$SVCUSER"
  mkdir -p "$ETC" "$DATA" "$LOGDIR" "$BACKUP"
  chown -R "$SVCUSER:$SVCUSER" "$DATA" "$LOGDIR"
  chmod 0750 "$DATA" "$LOGDIR"
}

port_in_use() { ss -ltnH "( sport = :$1 )" 2>/dev/null | grep -q . ; }

pick_backend_port() {
  local p="$BACKEND_PORT"
  while port_in_use "$p"; do p=$((p+1)); done
  BACKEND_PORT="$p"
}

detect_ws() {
  if systemctl is-active --quiet nginx 2>/dev/null; then echo nginx
  elif systemctl is-active --quiet apache2 2>/dev/null; then echo apache2
  else echo none; fi
}

relocate_nginx() {
  log "detected nginx — moving its HTTP :${WAF_PORT} to 127.0.0.1:${BACKEND_PORT}"
  tar czf "$BACKUP/nginx-$(date +%Y%m%d%H%M%S).tar.gz" -C / etc/nginx 2>/dev/null || true
  # IPv6 first, then IPv4/any, only the public WAF port, leaving 443 alone.
  grep -rlE "listen[[:space:]]+(\[::\]:|\*:)?${WAF_PORT}\b" /etc/nginx 2>/dev/null | while read -r f; do
    sed -E -i "s/listen([[:space:]]+)\[::\]:${WAF_PORT}\b/listen\1[::1]:${BACKEND_PORT}/g; \
               s/listen([[:space:]]+)(\*:)?${WAF_PORT}\b/listen\1127.0.0.1:${BACKEND_PORT}/g" "$f"
  done
  if ! nginx -t >/dev/null 2>&1; then
    warn "nginx config test failed after edit — restoring backup"
    tar xzf "$(ls -t "$BACKUP"/nginx-*.tar.gz | head -n1)" -C /
    die "aborted; your nginx config was restored"
  fi
  systemctl reload nginx
  BACKEND_URL="http://127.0.0.1:${BACKEND_PORT}"
}

relocate_apache() {
  log "detected apache2 — moving its HTTP :${WAF_PORT} to 127.0.0.1:${BACKEND_PORT}"
  tar czf "$BACKUP/apache2-$(date +%Y%m%d%H%M%S).tar.gz" -C / etc/apache2 2>/dev/null || true
  sed -E -i "s/^([[:space:]]*Listen[[:space:]]+)(\[::\]:|\*:)?${WAF_PORT}\b/\1127.0.0.1:${BACKEND_PORT}/g" /etc/apache2/ports.conf
  grep -rlE "<VirtualHost[[:space:]]+(\[::\]:|\*:)?${WAF_PORT}>" /etc/apache2 2>/dev/null | while read -r f; do
    sed -E -i "s/<VirtualHost([[:space:]]+)(\[::\]:|\*:)?${WAF_PORT}>/<VirtualHost\1127.0.0.1:${BACKEND_PORT}>/g" "$f"
  done
  local test_cmd="apache2ctl"; command -v apache2ctl >/dev/null 2>&1 || test_cmd="apachectl"
  if ! $test_cmd configtest >/dev/null 2>&1; then
    warn "apache2 config test failed after edit — restoring backup"
    tar xzf "$(ls -t "$BACKUP"/apache2-*.tar.gz | head -n1)" -C /
    die "aborted; your apache2 config was restored"
  fi
  systemctl reload apache2
  BACKEND_URL="http://127.0.0.1:${BACKEND_PORT}"
}

write_config() {
  local pass; pass="$(head -c 18 /dev/urandom | base64 | tr -d '/+=' | head -c 20)"
  DASH_PASS="$pass"
  cat > "$ETC/config.yaml" <<YAML
# ExactusWAF configuration (managed by install-linux.sh; safe to edit).
listen: "0.0.0.0:${WAF_PORT}"
backend: "${BACKEND_URL}"
mode: "${MODE}"

dashboard:
  enabled: true
  listen: "0.0.0.0:${DASH_PORT}"
  password: "${pass}"

rate_limit:
  enabled: true
  requests_per_minute: 240
  burst: 60

ip_blocklist: []
ip_allowlist: []

auto_ban:
  enabled: true
  max_strikes: 5
  window_minutes: 10
  ban_minutes: 60
  scope: "ip_ua"

# ExactusWAF is the public front and sees real client IPs, so keep this false
# unless you put it behind another trusted proxy (e.g. Cloudflare).
trust_proxy_headers: false

notify:
  telegram:
    enabled: false
    bot_token: ""
    chat_id: ""

tls:
  enabled: false
  cert_file: ""
  key_file: ""

rules_file: ""
log_file: "${LOGDIR}/exactuswaf.log"
data_dir: "${DATA}"
YAML
  chown root:"$SVCUSER" "$ETC/config.yaml"
  chmod 0640 "$ETC/config.yaml"
}

write_service() {
  cat > "$SVC" <<UNIT
[Unit]
Description=ExactusWAF - Web Application Firewall
After=network.target nginx.service apache2.service
Wants=network.target

[Service]
Type=simple
User=${SVCUSER}
Group=${SVCUSER}
WorkingDirectory=${DATA}
ExecStart=${BIN} -config ${ETC}/config.yaml
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
ReadWritePaths=${DATA} ${LOGDIR}
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
}

server_ip() {
  ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' \
    || hostname -I 2>/dev/null | awk '{print $1}'
}

do_install() {
  log "ExactusWAF installer for Ubuntu/Debian"
  command -v ss >/dev/null 2>&1 || { apt-get update -qq && apt-get install -y -qq iproute2; }

  build_binary
  make_user_dirs

  local ws; ws="none"
  if [ "$TOUCH_WS" = "1" ] && [ -z "$BACKEND_URL" ]; then
    ws="$(detect_ws)"
  fi

  if [ "$ws" = "nginx" ] || [ "$ws" = "apache2" ]; then
    pick_backend_port
    [ "$ws" = "nginx" ] && relocate_nginx || relocate_apache
    info "web server now serves internally at ${BACKEND_URL}; ExactusWAF will front it"
  else
    if [ -z "$BACKEND_URL" ]; then
      BACKEND_URL="http://127.0.0.1:${BACKEND_PORT}"
      warn "no running nginx/apache2 detected and no --backend given."
      warn "defaulting backend to ${BACKEND_URL} — change 'backend' in ${ETC}/config.yaml to your app."
    else
      info "protecting backend: ${BACKEND_URL}"
    fi
  fi

  if port_in_use "$WAF_PORT"; then
    die "port ${WAF_PORT} is still in use by another process; free it or pass --waf-port"
  fi

  write_config
  write_service
  systemctl enable --now exactuswaf >/dev/null 2>&1 || systemctl restart exactuswaf
  sleep 1
  systemctl is-active --quiet exactuswaf || { journalctl -u exactuswaf -n 20 --no-pager; die "exactuswaf failed to start"; }

  local sip; sip="$(server_ip)"
  echo
  log "ExactusWAF is installed and running."
  echo  "-------------------------------------------------------------"
  printf "  Protecting     : %s  (via ExactusWAF on port %s)\n" "$BACKEND_URL" "$WAF_PORT"
  printf "  Dashboard      : ${C_B}http://%s:%s${C_0}\n" "${sip:-<server-ip>}" "$DASH_PORT"
  printf "  Login          : admin  /  ${C_Y}%s${C_0}\n" "$DASH_PASS"
  printf "  Mode           : %s\n" "$MODE"
  echo  "-------------------------------------------------------------"
  info "Manage:  systemctl {status|restart|stop} exactuswaf"
  info "Config:  ${ETC}/config.yaml   Logs: journalctl -u exactuswaf -f"
  if [ "$MODE" = "block" ]; then
    warn "Running in BLOCK mode. If legitimate traffic gets blocked, switch to"
    warn "monitor first: set 'mode: monitor' in the config, then: systemctl restart exactuswaf"
  fi
  warn "SECURITY: the dashboard is exposed on port ${DASH_PORT}. Restrict it, e.g.:"
  warn "  ufw allow from <your-ip> to any port ${DASH_PORT}   (or use an SSH tunnel)"
  warn "HTTPS (443) is NOT fronted by this installer; only HTTP :${WAF_PORT} is. For TLS,"
  warn "terminate it at ExactusWAF (set tls.* in the config) or in front of it."
  info "Uninstall:  sudo bash install-linux.sh --uninstall"
}

do_uninstall() {
  log "uninstalling ExactusWAF"
  systemctl disable --now exactuswaf >/dev/null 2>&1 || true
  rm -f "$SVC"; systemctl daemon-reload
  # restore most recent web server backups if present
  local nb ab
  nb="$(ls -t "$BACKUP"/nginx-*.tar.gz 2>/dev/null | head -n1 || true)"
  ab="$(ls -t "$BACKUP"/apache2-*.tar.gz 2>/dev/null | head -n1 || true)"
  if [ -n "$nb" ]; then log "restoring nginx config from $nb"; tar xzf "$nb" -C /; nginx -t >/dev/null 2>&1 && systemctl reload nginx || true; fi
  if [ -n "$ab" ]; then log "restoring apache2 config from $ab"; tar xzf "$ab" -C /; systemctl reload apache2 || true; fi
  rm -f "$BIN"
  warn "kept ${ETC} (config/backups) and ${DATA} (Web ACLs). Remove manually if you want:"
  warn "  rm -rf ${ETC} ${DATA} ${LOGDIR}"
  log "done."
}

case "$ACTION" in
  install) do_install;;
  uninstall) do_uninstall;;
esac
