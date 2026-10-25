package dashboard

import (
	"encoding/json"
	"net/http"
	"strings"

	"exactuswaf/internal/settings"
	"exactuswaf/internal/sites"
	"exactuswaf/internal/stats"
	"exactuswaf/internal/waf"
	"exactuswaf/internal/webacl"
)

// ---- Helper respons JSON ----

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// readJSON membaca body JSON yang dibatasi ukurannya, dan menolak permintaan
// lintas situs (CSRF) pada endpoint yang mengubah data.
func (d *Dashboard) readJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	if !sameOrigin(r) {
		writeErr(w, http.StatusForbidden, "Request rejected (cross-site).")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeErr(w, http.StatusBadRequest, "The submitted data is invalid.")
		return false
	}
	return true
}

// ---- Meta & statistik ----

func (d *Dashboard) handleMeta(w http.ResponseWriter, r *http.Request) {
	active := d.deps.ACLs.Active()
	writeJSON(w, http.StatusOK, map[string]any{
		"mode":             d.deps.Mode(),
		"backend":          d.deps.Config.Backend,
		"listen":           d.deps.Config.Listen,
		"app_version":      d.deps.AppVersion,
		"rules_version":    d.deps.Catalog.Version,
		"rules_updated":    d.deps.Catalog.Updated,
		"rules_count":      d.deps.Catalog.Count(),
		"active_acl":       map[string]string{"id": active.ID, "name": active.Name},
		"autoban_enabled":  d.deps.Banner.Enabled(),
		"user":             adminUser,
		"session_max_hour": int(sessionTTL.Hours()),
	})
}

func (d *Dashboard) handleStats(w http.ResponseWriter, r *http.Request) {
	snap := d.deps.Stats.Snapshot()
	writeJSON(w, http.StatusOK, struct {
		stats.Snapshot
		Mode       string `json:"mode"`
		RulesCount int    `json:"rules_count"`
	}{snap, d.deps.Mode(), d.deps.Catalog.Count()})
}

func (d *Dashboard) handleSeries(w http.ResponseWriter, r *http.Request) {
	n := 60
	if v := r.URL.Query().Get("minutes"); v != "" {
		if parsed := atoiClamp(v, 5, 180); parsed > 0 {
			n = parsed
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"points": d.deps.Stats.Series(n)})
}

// ---- Signature catalog ----

type sigView struct {
	waf.Rule
	GroupID   string `json:"group_id"`
	GroupName string `json:"group_name"`
}

func (d *Dashboard) handleSignatures(w http.ResponseWriter, r *http.Request) {
	sigs := d.deps.Catalog.Signatures()
	views := make([]sigView, 0, len(sigs))
	for _, s := range sigs {
		g := waf.GroupOf(s.Category)
		views = append(views, sigView{Rule: s, GroupID: g.ID, GroupName: g.Name})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version":    d.deps.Catalog.Version,
		"updated":    d.deps.Catalog.Updated,
		"groups":     d.deps.Catalog.Groups(),
		"signatures": views,
	})
}

// ---- Web ACL ----

type aclSummary struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	RuleCount   int    `json:"rule_count"`
	BlockCount  int    `json:"block_count"`
	CountCount  int    `json:"count_count"`
	Capacity    int    `json:"capacity"`
	MaxCapacity int    `json:"max_capacity"`
	UpdatedAt   string `json:"updated_at"`
	Active      bool   `json:"active"`
}

func (d *Dashboard) summarize(a webacl.ACL, activeID string) aclSummary {
	block, count := 0, 0
	for _, r := range a.Rules {
		if r.Action == string(waf.ActionCount) {
			count++
		} else {
			block++
		}
	}
	return aclSummary{
		ID: a.ID, Name: a.Name, Description: a.Description,
		RuleCount: len(a.Rules), BlockCount: block, CountCount: count,
		Capacity: webacl.Capacity(d.deps.Catalog, a.Rules), MaxCapacity: webacl.MaxCapacity,
		UpdatedAt: a.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"), Active: a.ID == activeID,
	}
}

func (d *Dashboard) handleListACLs(w http.ResponseWriter, r *http.Request) {
	activeID := d.deps.ACLs.ActiveID()
	list := d.deps.ACLs.List()
	out := make([]aclSummary, 0, len(list))
	for _, a := range list {
		out = append(out, d.summarize(a, activeID))
	}
	writeJSON(w, http.StatusOK, map[string]any{"active_id": activeID, "acls": out})
}

// aclRuleView menggabungkan RuleRef dengan info signature yang dirujuk.
type aclRuleView struct {
	SignatureID string `json:"signature_id"`
	Action      string `json:"action"`
	Name        string `json:"name"`
	CVE         string `json:"cve"`
	Severity    string `json:"severity"`
	Category    string `json:"category"`
	Target      string `json:"target"`
	GroupID     string `json:"group_id"`
	GroupName   string `json:"group_name"`
}

func (d *Dashboard) aclDetail(a webacl.ACL, activeID string) map[string]any {
	rules := make([]aclRuleView, 0, len(a.Rules))
	for _, r := range a.Rules {
		sig, ok := d.deps.Catalog.Get(r.SignatureID)
		if !ok {
			continue
		}
		g := waf.GroupOf(sig.Category)
		rules = append(rules, aclRuleView{
			SignatureID: r.SignatureID, Action: r.Action, Name: sig.Name, CVE: sig.CVE,
			Severity: sig.Severity, Category: sig.Category, Target: sig.Target,
			GroupID: g.ID, GroupName: g.Name,
		})
	}
	return map[string]any{
		"id": a.ID, "name": a.Name, "description": a.Description,
		"created_at": a.CreatedAt, "updated_at": a.UpdatedAt,
		"active":       a.ID == activeID,
		"capacity":     webacl.Capacity(d.deps.Catalog, a.Rules),
		"max_capacity": webacl.MaxCapacity,
		"rules":        rules,
	}
}

func (d *Dashboard) handleGetACL(w http.ResponseWriter, r *http.Request) {
	a, ok := d.deps.ACLs.Get(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "Web ACL not found.")
		return
	}
	writeJSON(w, http.StatusOK, d.aclDetail(a, d.deps.ACLs.ActiveID()))
}

type aclInput struct {
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Rules       []webacl.RuleRef `json:"rules"`
}

func (d *Dashboard) handleCreateACL(w http.ResponseWriter, r *http.Request) {
	var in aclInput
	if !d.readJSON(w, r, &in) {
		return
	}
	webacl.SortRefsByCatalog(d.deps.Catalog, in.Rules)
	a, err := d.deps.ACLs.Create(in.Name, in.Description, in.Rules)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, d.aclDetail(a, d.deps.ACLs.ActiveID()))
}

func (d *Dashboard) handleUpdateACL(w http.ResponseWriter, r *http.Request) {
	var in aclInput
	if !d.readJSON(w, r, &in) {
		return
	}
	webacl.SortRefsByCatalog(d.deps.Catalog, in.Rules)
	a, err := d.deps.ACLs.Update(r.PathValue("id"), in.Name, in.Description, in.Rules)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, d.aclDetail(a, d.deps.ACLs.ActiveID()))
}

func (d *Dashboard) handleDeleteACL(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		writeErr(w, http.StatusForbidden, "Request rejected (cross-site).")
		return
	}
	if err := d.deps.ACLs.Delete(r.PathValue("id")); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (d *Dashboard) handleActivateACL(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		writeErr(w, http.StatusForbidden, "Request rejected (cross-site).")
		return
	}
	if err := d.deps.ACLs.SetActive(r.PathValue("id")); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"active_id": d.deps.ACLs.ActiveID()})
}

// ---- Shield ----

func (d *Dashboard) handleShield(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, d.shieldPayload())
}

// shieldPayload builds the Shield JSON from the live settings store + ban list.
func (d *Dashboard) shieldPayload() map[string]any {
	st := d.deps.Settings.Get()
	return map[string]any{
		"autoban": map[string]any{
			"enabled": st.AutoBan.Enabled, "max_strikes": st.AutoBan.MaxStrikes,
			"window_minutes": st.AutoBan.WindowMinutes, "ban_minutes": st.AutoBan.BanMinutes, "scope": st.AutoBan.Scope,
		},
		"bans":      nonNil(d.deps.Banner.List()),
		"blocklist": nonNil(st.Blocklist),
		"allowlist": nonNil(st.Allowlist),
		"rate_limit": map[string]any{
			"enabled":             st.RateLimit.Enabled,
			"requests_per_minute": st.RateLimit.RequestsPerMinute,
			"burst":               st.RateLimit.Burst,
		},
		"trust_proxy_headers": d.deps.Config.TrustProxyHeaders,
	}
}

type shieldInput struct {
	AutoBan struct {
		Enabled       bool   `json:"enabled"`
		MaxStrikes    int    `json:"max_strikes"`
		WindowMinutes int    `json:"window_minutes"`
		BanMinutes    int    `json:"ban_minutes"`
		Scope         string `json:"scope"`
	} `json:"auto_ban"`
	RateLimit struct {
		Enabled           bool `json:"enabled"`
		RequestsPerMinute int  `json:"requests_per_minute"`
		Burst             int  `json:"burst"`
	} `json:"rate_limit"`
}

func (d *Dashboard) handleUpdateShield(w http.ResponseWriter, r *http.Request) {
	var in shieldInput
	if !d.readJSON(w, r, &in) {
		return
	}
	_, err := d.deps.Settings.UpdateShield(
		settings.RateLimit{Enabled: in.RateLimit.Enabled, RequestsPerMinute: in.RateLimit.RequestsPerMinute, Burst: in.RateLimit.Burst},
		settings.AutoBan{Enabled: in.AutoBan.Enabled, MaxStrikes: in.AutoBan.MaxStrikes,
			WindowMinutes: in.AutoBan.WindowMinutes, BanMinutes: in.AutoBan.BanMinutes, Scope: in.AutoBan.Scope},
	)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, d.shieldPayload())
}

// ---- IP sets ----

func (d *Dashboard) handleIPSets(w http.ResponseWriter, r *http.Request) {
	st := d.deps.Settings.Get()
	writeJSON(w, http.StatusOK, map[string]any{
		"blocklist": nonNil(st.Blocklist),
		"allowlist": nonNil(st.Allowlist),
	})
}

type ipSetsInput struct {
	Blocklist []string `json:"blocklist"`
	Allowlist []string `json:"allowlist"`
}

func (d *Dashboard) handleUpdateIPSets(w http.ResponseWriter, r *http.Request) {
	var in ipSetsInput
	if !d.readJSON(w, r, &in) {
		return
	}
	out, err := d.deps.Settings.UpdateIPSets(in.Blocklist, in.Allowlist)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"blocklist": nonNil(out.Blocklist),
		"allowlist": nonNil(out.Allowlist),
	})
}

type unbanInput struct {
	Key string `json:"key"`
}

func (d *Dashboard) handleUnban(w http.ResponseWriter, r *http.Request) {
	var in unbanInput
	if !d.readJSON(w, r, &in) {
		return
	}
	if strings.TrimSpace(in.Key) == "" || !d.deps.Banner.Unban(in.Key) {
		writeErr(w, http.StatusBadRequest, "Ban not found or already expired.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---- Applications (multi-site) ----

type siteView struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Domains   []string `json:"domains"`
	Backend   string   `json:"backend"`
	Port      int      `json:"port"`
	Requests  uint64   `json:"requests"`
	Blocked   uint64   `json:"blocked"`
	IsDefault bool     `json:"is_default"`
	CreatedAt string   `json:"created_at,omitempty"`
	UpdatedAt string   `json:"updated_at,omitempty"`
}

func (d *Dashboard) handleListSites(w http.ResponseWriter, r *http.Request) {
	traffic := d.deps.Stats.SiteStats()
	// The default backend (config.yaml) is the catch-all app, shown first.
	def := traffic["default"]
	out := []siteView{{
		Name: "Default (catch-all)", Backend: d.deps.Config.Backend,
		Requests: def.Requests, Blocked: def.Blocked, IsDefault: true, Domains: []string{},
	}}
	for _, s := range d.deps.Sites.List() {
		t := traffic[s.Name]
		out = append(out, siteView{
			ID: s.ID, Name: s.Name, Domains: nonNil(s.Domains), Backend: s.Backend, Port: s.Port,
			Requests: t.Requests, Blocked: t.Blocked,
			CreatedAt: s.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
			UpdatedAt: s.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"default_backend": d.deps.Config.Backend, "sites": out})
}

type siteInput struct {
	Name    string   `json:"name"`
	Domains []string `json:"domains"`
	Backend string   `json:"backend"`
	Port    int      `json:"port"`
}

func (d *Dashboard) handleCreateSite(w http.ResponseWriter, r *http.Request) {
	var in siteInput
	if !d.readJSON(w, r, &in) {
		return
	}
	s, err := d.deps.Sites.Create(sites.Site{Name: in.Name, Domains: in.Domains, Backend: in.Backend, Port: in.Port})
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": s.ID, "port_needs_restart": s.Port > 0})
}

func (d *Dashboard) handleUpdateSite(w http.ResponseWriter, r *http.Request) {
	var in siteInput
	if !d.readJSON(w, r, &in) {
		return
	}
	s, err := d.deps.Sites.Update(r.PathValue("id"), sites.Site{Name: in.Name, Domains: in.Domains, Backend: in.Backend, Port: in.Port})
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": s.ID, "port_needs_restart": s.Port > 0})
}

func (d *Dashboard) handleDeleteSite(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		writeErr(w, http.StatusForbidden, "Request rejected (cross-site).")
		return
	}
	if err := d.deps.Sites.Delete(r.PathValue("id")); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---- Settings & mode ----

func (d *Dashboard) handleSettings(w http.ResponseWriter, r *http.Request) {
	c := d.deps.Config
	st := d.deps.Settings.Get()
	writeJSON(w, http.StatusOK, map[string]any{
		"mode": d.deps.Mode(), "backend": c.Backend, "listen": c.Listen,
		"dashboard_listen": c.Dashboard.Listen,
		"rate_limit": map[string]any{
			"enabled": st.RateLimit.Enabled, "requests_per_minute": st.RateLimit.RequestsPerMinute, "burst": st.RateLimit.Burst,
		},
		"auto_ban": map[string]any{
			"enabled": st.AutoBan.Enabled, "max_strikes": st.AutoBan.MaxStrikes,
			"window_minutes": st.AutoBan.WindowMinutes, "ban_minutes": st.AutoBan.BanMinutes, "scope": st.AutoBan.Scope,
		},
		"trust_proxy_headers": c.TrustProxyHeaders,
		"tls_enabled":         c.TLS.Enabled,
		"telegram_enabled":    c.Notify.Telegram.Enabled,
		"log_file":            c.LogFile,
		"rules_file":          c.RulesFile,
		"data_dir":            c.DataDir,
	})
}

type modeInput struct {
	Mode string `json:"mode"`
}

func (d *Dashboard) handleSetMode(w http.ResponseWriter, r *http.Request) {
	var in modeInput
	if !d.readJSON(w, r, &in) {
		return
	}
	if err := d.deps.SetMode(in.Mode); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"mode": d.deps.Mode()})
}

// ---- util ----

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func atoiClamp(s string, lo, hi int) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
		if n > hi {
			return hi
		}
	}
	if n < lo {
		return lo
	}
	return n
}
