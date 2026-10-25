package waf

import (
	"io"
	"net/http"
	neturl "net/url"
	"strings"
)

// Match adalah hasil ketika sebuah signature cocok dengan permintaan.
type Match struct {
	RuleID   string
	RuleName string
	CVE      string
	Severity string
	Category string
	Action   Action // aksi signature ini di Web ACL aktif (block/count)
	Location string // di mana ditemukan: url/header/body
	Evidence string // potongan teks yang memicu (dipangkas)
}

// maxBodyInspect membatasi berapa banyak body yang diperiksa (mencegah boros memori).
const maxBodyInspect = 512 * 1024 // 512 KB

// PlanSpec adalah satu baris rencana: signature mana, dengan aksi apa.
type PlanSpec struct {
	SignatureID string
	Action      Action
}

// planEntry adalah signature terkompilasi + aksinya dalam satu Web ACL.
type planEntry struct {
	rule   *compiledRule
	action Action
}

// Plan adalah rencana evaluasi untuk satu Web ACL aktif: daftar signature terurut
// beserta aksinya. Plan bersifat read-only sehingga aman dipakai banyak goroutine.
type Plan struct {
	entries []planEntry
}

// BuildPlan menyusun Plan dari daftar PlanSpec. Signature yang tidak ada di
// katalog diabaikan (dianggap sudah dibuang). Aksi kosong dianggap block.
func (c *Catalog) BuildPlan(specs []PlanSpec) *Plan {
	p := &Plan{}
	for _, s := range specs {
		cr, ok := c.byID[s.SignatureID]
		if !ok {
			continue
		}
		action := s.Action
		if !ValidAction(action) {
			action = ActionBlock
		}
		p.entries = append(p.entries, planEntry{rule: cr, action: action})
	}
	return p
}

// Len mengembalikan jumlah signature aktif dalam plan.
func (p *Plan) Len() int { return len(p.entries) }

// Decision adalah hasil evaluasi satu permintaan terhadap sebuah Plan.
type Decision struct {
	Block  *Match   // signature beraksi "block" pertama yang cocok (nil bila tidak ada)
	Counts []*Match // signature beraksi "count" yang cocok sebelum block
}

// Matched true bila ada signature apa pun yang cocok.
func (d Decision) Matched() bool { return d.Block != nil || len(d.Counts) > 0 }

// requestTexts menyiapkan teks yang diperiksa dari sebuah permintaan: URL
// (termasuk hasil decode berlapis), header, dan body.
func requestTexts(r *http.Request, bodyBytes []byte) (url, headers, body string) {
	rawURL := r.URL.RequestURI()
	url = rawURL
	if d, err := neturl.QueryUnescape(rawURL); err == nil {
		url += " " + d
		if d2, err := neturl.QueryUnescape(d); err == nil {
			url += " " + d2
		}
	}
	return url, headerString(r), string(bodyBytes)
}

// Evaluate memeriksa permintaan terhadap semua signature dalam plan. Signature
// beraksi "count" dicatat lalu evaluasi lanjut; signature beraksi "block"
// pertama yang cocok menghentikan evaluasi (permintaan akan ditolak).
func (p *Plan) Evaluate(r *http.Request, bodyBytes []byte) Decision {
	urlText, headers, body := requestTexts(r, bodyBytes)
	var dec Decision
	for i := range p.entries {
		e := &p.entries[i]
		m := matchRule(e.rule, urlText, headers, body)
		if m == nil {
			continue
		}
		m.Action = e.action
		if e.action == ActionBlock {
			dec.Block = m
			return dec
		}
		dec.Counts = append(dec.Counts, m)
	}
	return dec
}

// matchRule mencocokkan satu signature terhadap target yang relevan.
func matchRule(cr *compiledRule, urlText, headers, body string) *Match {
	switch cr.Target {
	case "url":
		return scan(cr, urlText, "url")
	case "header":
		return scan(cr, headers, "header")
	case "body":
		return scan(cr, body, "body")
	default: // "all"
		if m := scan(cr, urlText, "url"); m != nil {
			return m
		}
		if m := scan(cr, headers, "header"); m != nil {
			return m
		}
		if body != "" {
			return scan(cr, body, "body")
		}
		return nil
	}
}

func scan(cr *compiledRule, text, location string) *Match {
	loc := cr.re.FindStringIndex(text)
	if loc == nil {
		return nil
	}
	return &Match{
		RuleID:   cr.ID,
		RuleName: cr.Name,
		CVE:      cr.CVE,
		Severity: cr.Severity,
		Category: cr.Category,
		Location: location,
		Evidence: snippet(text, loc[0], loc[1]),
	}
}

// snippet mengambil potongan singkat di sekitar kecocokan untuk log.
func snippet(text string, start, end int) string {
	const pad = 20
	s := start - pad
	if s < 0 {
		s = 0
	}
	e := end + pad
	if e > len(text) {
		e = len(text)
	}
	out := text[s:e]
	if len(out) > 120 {
		out = out[:120]
	}
	return strings.TrimSpace(out)
}

func headerString(r *http.Request) string {
	var b strings.Builder
	b.WriteString(r.UserAgent())
	b.WriteByte('\n')
	b.WriteString(r.Referer())
	b.WriteByte('\n')
	for name, vals := range r.Header {
		// Lewati header yang selalu berisik dan tidak berguna untuk deteksi.
		if name == "Cookie" {
			continue
		}
		for _, v := range vals {
			b.WriteString(name)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// ReadBodyLimited membaca body permintaan sampai batas aman untuk diperiksa,
// lalu mengembalikannya agar pemanggil dapat mengembalikan body ke request.
func ReadBodyLimited(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	return io.ReadAll(io.LimitReader(r.Body, maxBodyInspect))
}
