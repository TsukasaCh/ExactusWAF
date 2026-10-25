<div align="center">

# 🛡️ ExactusWAF

**A simple, self-hosted Web Application Firewall written in Go.**

It sits in front of your website as a reverse proxy and filters attacks
(SQL injection, XSS, RCE, path traversal, Log4Shell, 700+ CVE & generic
signatures) **before** they reach your app — managed from an AWS-style console.

</div>

```
   Visitors   ──►   🛡️ ExactusWAF   ──►   Your website
   (& attackers)     (inspect & block)      (only clean traffic)
```

---

## ✨ Features

- **730+ detection signatures** (v2026.10.2) — recent CVEs (SharePoint ToolShell,
  FortiWeb, wp2shell, react2shell, Log4Shell, Spring4Shell, …) plus broad generic
  classes: SQLi, XSS, RCE/command injection, LFI/path traversal, SSTI,
  insecure deserialization, SSRF, NoSQL injection, XXE, webshell uploads,
  auth/JWT bypass, scanners and sensitive-file probing.
- **Web ACL console** — a management UI (like AWS WAF & Shield): compose your own
  Web ACL from the signature catalog and set each signature to **Block** or
  **Count**. Changes apply to the live engine instantly, no restart.
- **Shield** — automatic temporary IP ban for repeat attackers (CGNAT-safe
  `ip_ua` scope) and per-IP rate limiting.
- **Real-time dashboard** — traffic chart, top rules/IPs, recent attacks,
  light/dark theme. Session login with brute-force lockout.
- **Runs anywhere** — one-command installer for Ubuntu/Debian, Docker (Windows
  containers), or build from source. Rules & console are embedded in the binary.
- **Monitor mode** — try rules without blocking before you enforce them.

---

## 🚀 Quick start — Ubuntu / Debian (recommended)

The installer builds ExactusWAF, puts it **in front of your existing web server**
(nginx or apache2), and runs it as a `systemd` service.

```bash
# 1. Get the code
git clone https://github.com/TsukasaCh/ExactusWAF.git
cd ExactusWAF

# 2. Run the installer as root
sudo bash install-linux.sh
```

That's it. The installer will:

1. Build the `exactuswaf` binary (it downloads Go automatically if needed).
2. Detect **nginx** or **apache2**, back up its config, and move it to an
   internal port (`127.0.0.1:8080`) — only the HTTP `:80` listeners are changed,
   `:443` is left untouched.
3. Put **ExactusWAF on port 80** so it inspects every request and forwards clean
   traffic to your site (your app still sees the real client IP via
   `X-Forwarded-For`).
4. Start the service and print the **dashboard URL, username and a random password**.

Open the dashboard at **`http://<your-server-ip>:8991`** and log in as `admin`
with the password shown by the installer.

**Options:**

| Flag | Meaning | Default |
|---|---|---|
| `--backend URL` | Protect this backend when no web server is detected (e.g. `http://127.0.0.1:3000`) | auto |
| `--mode block\|monitor` | Start mode | `block` |
| `--dash-port N` | Dashboard port | `8991` |
| `--waf-port N` | Public port ExactusWAF listens on | `80` |
| `--no-webserver` | Don't touch nginx/apache; just use `--backend` | — |
| `--uninstall` | Remove ExactusWAF and restore the web server config from backup | — |

Manage the service:

```bash
systemctl status exactuswaf      # is it running?
systemctl restart exactuswaf     # after editing the config
journalctl -u exactuswaf -f      # live logs
```

Configuration lives at `/etc/exactuswaf/config.yaml`.
Uninstall with `sudo bash install-linux.sh --uninstall`.

---

## 🐳 Run with Docker (Windows Server / Windows containers)

> The included `Dockerfile` and `docker-compose.yml` target **Windows containers**
> (Nano Server). On Linux, use the installer above or build from source.

```powershell
docker compose up -d --build
```

- Website through the WAF: `http://localhost:8080`
- Dashboard: double-click `Dashboard-ExactusWAF.bat` (it finds the container IP;
  the dashboard port is intentionally not published to the network)
- Edit `docker\config.yaml` then `docker compose up -d --build` to apply changes.
- The sample `example-site` service is only there to demo protection — remove it
  and point `backend` at your real site.

---

## 🔧 Run from source (any OS with Go ≥ 1.24)

```bash
go build -o exactuswaf .     # or: go build -o exactuswaf.exe . on Windows
cp config.yaml myconfig.yaml # edit "backend" to point at your site
./exactuswaf -config myconfig.yaml
```

Visitors go through `listen` (default `0.0.0.0:8080`); the dashboard is on
`dashboard.listen`.

---

## 🧭 Using the console

1. **Log in** at the dashboard URL (user `admin`, password from the installer or
   `dashboard.password` in the config).
2. **Overview** shows live traffic (allowed / blocked / counted), top signatures
   and IPs, and recent attacks.
3. **Web ACL** → *Create Web ACL*: pick signatures from the catalog and set each
   to **Block** (reject the request) or **Count** (log only, let it through —
   great for testing). Save, then **Activate** it — it applies instantly.
4. **Signatures** browses the full catalog (filter by name/CVE/group).
5. **Shield** shows auto-ban settings and currently blocked IPs (with *Unblock*).
6. **Settings** lets you switch between **Block** and **Monitor** mode live.

> **Tip:** for a brand-new deployment, run in **Monitor mode** for a day first.
> Everything is only counted, so you can confirm no legitimate visitor is caught
> before switching to **Block**.

---

## ⚙️ Configuration (`config.yaml`)

| Key | Meaning |
|---|---|
| `listen` | Address ExactusWAF listens on (what visitors hit) |
| `backend` | Your real website/app, e.g. `http://127.0.0.1:8080` |
| `mode` | `block` (reject attacks) or `monitor` (count only) |
| `dashboard.listen` / `dashboard.password` | Console address and admin password |
| `rate_limit` | Requests per minute per IP, with burst |
| `auto_ban` | Temporary ban for repeat attackers; `scope: ip_ua` is CGNAT-safe |
| `ip_blocklist` / `ip_allowlist` | Always-block / always-allow IPs |
| `trust_proxy_headers` | `true` only if behind another trusted proxy (nginx/Cloudflare) |
| `tls` | Optional HTTPS (cert/key paths) |
| `data_dir` | Where Web ACLs are persisted |
| `rules_file` | Custom rules file; empty = use the built-in catalog |

---

## 🔒 Security notes

- The dashboard is an **admin interface**. Restrict access to it, e.g.
  `ufw allow from <your-ip> to any port 8991`, or reach it over an SSH tunnel.
  Always change the default/placeholder password.
- The Linux installer fronts **HTTP (:80)** only. For HTTPS, terminate TLS at
  ExactusWAF (`tls.*` in the config) or in front of it.
- ExactusWAF is **one layer** of defense — keep your software patched and keep
  good input validation in your app too.

---

<div align="center">

**MIT License** — free to use, share and modify.

Make your web safer. 🛡️

</div>
