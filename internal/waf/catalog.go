// Package waf berisi mesin deteksi: katalog signature, rencana (plan) per Web ACL,
// dan pemeriksaan permintaan HTTP.
package waf

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
)

// cve_rules.json bawaan ditanam langsung ke dalam binary, sehingga ExactusWAF
// tetap berfungsi tanpa file eksternal apa pun (ramah untuk orang awam).
//
//go:embed embedded_rules.json
var embeddedRules []byte

// Action adalah aksi untuk sebuah signature di dalam Web ACL.
//
//	ActionBlock = permintaan yang cocok diblokir (HTTP 403).
//	ActionCount = permintaan yang cocok hanya dihitung/dicatat, tetap diteruskan.
type Action string

const (
	ActionBlock Action = "block"
	ActionCount Action = "count"
)

// ValidAction memastikan aksi yang dikirim dari API memang dikenal.
func ValidAction(a Action) bool { return a == ActionBlock || a == ActionCount }

// Rule adalah satu signature deteksi mentah dari file JSON / katalog.
type Rule struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	CVE      string `json:"cve"`
	Severity string `json:"severity"`
	Category string `json:"category"`
	Target   string `json:"target"` // url | header | body | all
	Pattern  string `json:"pattern"`
}

// compiledRule adalah Rule yang regex-nya sudah dikompilasi agar cepat.
type compiledRule struct {
	Rule
	re *regexp.Regexp
}

type ruleFile struct {
	Version string `json:"version"`
	Updated string `json:"updated"`
	Rules   []Rule `json:"rules"`
}

// Catalog adalah seluruh signature yang tersedia (sudah dikompilasi). Web ACL
// memilih sebagian dari katalog ini dan menentukan aksinya.
type Catalog struct {
	Version string
	Updated string
	rules   []compiledRule
	byID    map[string]*compiledRule
}

// LoadCatalog memuat katalog dari path. Jika path kosong, pakai aturan bawaan.
func LoadCatalog(path string) (*Catalog, error) {
	var data []byte
	var err error
	if path == "" {
		data = embeddedRules
	} else {
		data, err = os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("cannot read rules file %q: %w", path, err)
		}
	}

	var rf ruleFile
	if err := json.Unmarshal(data, &rf); err != nil {
		return nil, fmt.Errorf("invalid rules file format: %w", err)
	}

	c := &Catalog{Version: rf.Version, Updated: rf.Updated, byID: make(map[string]*compiledRule)}
	for _, r := range rf.Rules {
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return nil, fmt.Errorf("broken regex pattern in rule %s: %w", r.ID, err)
		}
		if r.Target == "" {
			r.Target = "all"
		}
		c.rules = append(c.rules, compiledRule{Rule: r, re: re})
	}
	if len(c.rules) == 0 {
		return nil, fmt.Errorf("no rules loaded")
	}
	for i := range c.rules {
		c.byID[c.rules[i].ID] = &c.rules[i]
	}
	return c, nil
}

// LoadRules dipertahankan sebagai alias lama agar kode/test yang ada tetap jalan.
func LoadRules(path string) (*Catalog, error) { return LoadCatalog(path) }

// Count mengembalikan jumlah signature dalam katalog.
func (c *Catalog) Count() int { return len(c.rules) }

// Has mengecek apakah sebuah signature ada di katalog.
func (c *Catalog) Has(id string) bool { _, ok := c.byID[id]; return ok }

// Get mengembalikan satu signature mentah.
func (c *Catalog) Get(id string) (Rule, bool) {
	if cr, ok := c.byID[id]; ok {
		return cr.Rule, true
	}
	return Rule{}, false
}

// Signatures mengembalikan semua signature (urut sesuai file) untuk API katalog.
func (c *Catalog) Signatures() []Rule {
	out := make([]Rule, len(c.rules))
	for i := range c.rules {
		out[i] = c.rules[i].Rule
	}
	return out
}

// Group adalah pengelompokan signature berdasarkan kategori (untuk tampilan UI
// seperti "rule group" di AWS WAF).
type Group struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// groupInfo memetakan kategori signature ke grup yang ramah dibaca. Urutan slice
// menentukan urutan tampil di konsol.
var groupInfo = []Group{
	{"sqli", "SQL Injection", "Attempts to steal or corrupt database contents via input."},
	{"nosqli", "NoSQL Injection", "Injection into NoSQL databases such as MongoDB."},
	{"xss", "Cross-Site Scripting (XSS)", "Injecting malicious scripts into a victim page."},
	{"traversal", "Path Traversal / LFI", "Reading sensitive files on the server."},
	{"rce", "Command Injection / RCE", "Running commands on your server."},
	{"ssti", "Server-Side Template Injection", "Template injection leading to code execution."},
	{"deserialization", "Unsafe Deserialization", "Malicious objects executed during deserialization."},
	{"ssrf", "Server-Side Request Forgery", "Forcing the server to reach internal resources."},
	{"xxe", "XML External Entity (XXE)", "Attacks via malicious XML documents."},
	{"fileupload", "Upload / Webshell", "Attempts to plant a webshell or malicious file."},
	{"authbypass", "Authentication Bypass", "Bypassing login/authorization checks."},
	{"scanner", "Automated Scanners", "Vulnerability scanning tools (sqlmap, nikto, etc.)."},
	{"recon", "Sensitive File Access", "Probing config/secret files (.env, .git)."},
	{"other", "Other", "Signatures that do not fit the categories above."},
}

// GroupOf mengembalikan grup untuk sebuah kategori signature.
func GroupOf(category string) Group {
	for _, g := range groupInfo {
		if g.ID == category {
			return g
		}
	}
	return groupInfo[len(groupInfo)-1] // "other"
}

// Groups mengembalikan daftar grup yang BENAR-BENAR dipakai oleh katalog, lengkap
// dengan jumlah signature per grup, untuk daftar rule group di konsol.
func (c *Catalog) Groups() []GroupSummary {
	count := map[string]int{}
	for i := range c.rules {
		count[GroupOf(c.rules[i].Category).ID]++
	}
	var out []GroupSummary
	for _, g := range groupInfo {
		if n := count[g.ID]; n > 0 {
			out = append(out, GroupSummary{Group: g, SignatureCount: n})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].SignatureCount > out[j].SignatureCount })
	return out
}

// GroupSummary adalah grup beserta jumlah signature-nya.
type GroupSummary struct {
	Group
	SignatureCount int `json:"signature_count"`
}
