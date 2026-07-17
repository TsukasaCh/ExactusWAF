// Package waf berisi mesin deteksi: memuat aturan dan memeriksa permintaan HTTP.
package waf

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
)

// cve_rules.json bawaan ditanam langsung ke dalam binary, sehingga ExactusWAF
// tetap berfungsi tanpa file eksternal apa pun (ramah untuk orang awam).
//
//go:embed embedded_rules.json
var embeddedRules []byte

// Rule adalah satu aturan deteksi mentah dari file JSON.
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

// RuleSet menyimpan semua aturan yang siap dipakai.
type RuleSet struct {
	Version string
	Updated string
	rules   []compiledRule
}

// LoadRules memuat aturan dari path. Jika path kosong, gunakan aturan bawaan.
func LoadRules(path string) (*RuleSet, error) {
	var data []byte
	var err error
	if path == "" {
		data = embeddedRules
	} else {
		data, err = os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("tidak bisa membaca file aturan %q: %w", path, err)
		}
	}

	var rf ruleFile
	if err := json.Unmarshal(data, &rf); err != nil {
		return nil, fmt.Errorf("format file aturan tidak valid: %w", err)
	}

	rs := &RuleSet{Version: rf.Version, Updated: rf.Updated}
	for _, r := range rf.Rules {
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return nil, fmt.Errorf("pola regex rusak pada aturan %s: %w", r.ID, err)
		}
		if r.Target == "" {
			r.Target = "all"
		}
		rs.rules = append(rs.rules, compiledRule{Rule: r, re: re})
	}
	if len(rs.rules) == 0 {
		return nil, fmt.Errorf("tidak ada aturan yang dimuat")
	}
	return rs, nil
}

// Count mengembalikan jumlah aturan yang aktif.
func (rs *RuleSet) Count() int { return len(rs.rules) }
