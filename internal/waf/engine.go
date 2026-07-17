package waf

import (
	"io"
	"net/http"
	neturl "net/url"
	"strings"
)

// Match adalah hasil ketika sebuah aturan cocok dengan permintaan.
type Match struct {
	RuleID   string
	RuleName string
	CVE      string
	Severity string
	Category string
	Location string // di mana ditemukan: url/header/body
	Evidence string // potongan teks yang memicu (dipangkas)
}

// maxBodyInspect membatasi berapa banyak body yang diperiksa (mencegah boros memori).
const maxBodyInspect = 512 * 1024 // 512 KB

// Inspect memeriksa satu permintaan terhadap semua aturan.
// Mengembalikan match pertama (paling relevan) atau nil bila bersih.
// bodyBytes adalah isi body yang sudah dibaca oleh pemanggil.
func (rs *RuleSet) Inspect(r *http.Request, bodyBytes []byte) *Match {
	rawURL := r.URL.RequestURI()
	// Periksa URL dalam bentuk mentah DAN yang sudah di-decode (bahkan decode
	// ganda), supaya payload ter-encode seperti %20/%252e tidak bisa mengelabui.
	urlDecoded := rawURL
	if d, err := neturl.QueryUnescape(rawURL); err == nil {
		urlDecoded += " " + d
		if d2, err := neturl.QueryUnescape(d); err == nil {
			urlDecoded += " " + d2
		}
	}

	headers := headerString(r)
	body := string(bodyBytes)

	for i := range rs.rules {
		cr := &rs.rules[i]
		switch cr.Target {
		case "url":
			if m := scan(cr, urlDecoded, "url"); m != nil {
				return m
			}
		case "header":
			if m := scan(cr, headers, "header"); m != nil {
				return m
			}
		case "body":
			if m := scan(cr, body, "body"); m != nil {
				return m
			}
		default: // "all"
			if m := scan(cr, urlDecoded, "url"); m != nil {
				return m
			}
			if m := scan(cr, headers, "header"); m != nil {
				return m
			}
			if body != "" {
				if m := scan(cr, body, "body"); m != nil {
					return m
				}
			}
		}
	}
	return nil
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
