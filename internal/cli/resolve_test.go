package cli

import "testing"

func TestNormalizeBackend(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"http://127.0.0.1:3000", "http://127.0.0.1:3000", true},
		{"https://app.local:8443/", "https://app.local:8443", true},
		{"127.0.0.1:3000", "http://127.0.0.1:3000", true},
		{"app.internal:8080", "http://app.internal:8080", true},
		{":5000", "http://127.0.0.1:5000", true},
		{"5000", "http://127.0.0.1:5000", true},
		{"not a port", "", false},
		{"example.com", "", false}, // no port -> ambiguous, reject
		{"", "", false},
	}
	for _, c := range cases {
		got, err := normalizeBackend(c.in)
		if c.ok && (err != nil || got != c.want) {
			t.Errorf("normalizeBackend(%q) = %q,%v; want %q", c.in, got, err, c.want)
		}
		if !c.ok && err == nil {
			t.Errorf("normalizeBackend(%q) should have failed, got %q", c.in, got)
		}
	}
}

func TestParseDockerInspect(t *testing.T) {
	j := []byte(`[{"Name":"/myapp","NetworkSettings":{"IPAddress":"",
	  "Networks":{"bridge":{"IPAddress":"172.17.0.5"}},
	  "Ports":{"3000/tcp":[{"HostIp":"0.0.0.0","HostPort":"3000"}],"9229/tcp":null}},
	  "Config":{"ExposedPorts":{"3000/tcp":{},"9229/tcp":{}}}}]`)
	ip, port, err := parseDockerInspect(j, 0)
	if err != nil || ip != "172.17.0.5" || port != 3000 {
		t.Fatalf("got ip=%q port=%d err=%v; want 172.17.0.5/3000", ip, port, err)
	}
	// port override wins
	if _, port, _ := parseDockerInspect(j, 8080); port != 8080 {
		t.Fatalf("override: got port=%d, want 8080", port)
	}
	// legacy top-level IPAddress
	j2 := []byte(`[{"Name":"/x","NetworkSettings":{"IPAddress":"10.0.0.2","Ports":{"80/tcp":null}},"Config":{"ExposedPorts":{"80/tcp":{}}}}]`)
	if ip, port, err := parseDockerInspect(j2, 0); err != nil || ip != "10.0.0.2" || port != 80 {
		t.Fatalf("legacy: got %q/%d/%v", ip, port, err)
	}
	// no ports -> error
	j3 := []byte(`[{"Name":"/x","NetworkSettings":{"IPAddress":"10.0.0.3"},"Config":{}}]`)
	if _, _, err := parseDockerInspect(j3, 0); err == nil {
		t.Fatal("expected error when no ports exposed")
	}
	// no IP -> error
	j4 := []byte(`[{"Name":"/x","NetworkSettings":{},"Config":{"ExposedPorts":{"80/tcp":{}}}}]`)
	if _, _, err := parseDockerInspect(j4, 0); err == nil {
		t.Fatal("expected error when container has no IP")
	}
	// published public port detection (0.0.0.0:3000)
	if pp := dockerPublicPorts(j); len(pp) != 1 || pp[0] != 3000 {
		t.Fatalf("dockerPublicPorts = %v, want [3000]", pp)
	}
	// localhost-published: not a PUBLIC bypass, but still a host publish that
	// would block the WAF's bind on that port.
	jLocal := []byte(`[{"Name":"/x","NetworkSettings":{"IPAddress":"172.18.0.3","Ports":{"8787/tcp":[{"HostIp":"127.0.0.1","HostPort":"8787"}]}},"Config":{"ExposedPorts":{"8787/tcp":{}}}}]`)
	if pp := dockerPublicPorts(jLocal); len(pp) != 0 {
		t.Fatalf("dockerPublicPorts(localhost-bound) = %v, want []", pp)
	}
	if hp := dockerHostPorts(jLocal, false); len(hp) != 1 || hp[0] != 8787 {
		t.Fatalf("dockerHostPorts(all) = %v, want [8787]", hp)
	}
	// expose-only (no publish): no host ports at all.
	jExpose := []byte(`[{"Name":"/x","NetworkSettings":{"IPAddress":"172.18.0.3","Ports":{"8787/tcp":null}},"Config":{"ExposedPorts":{"8787/tcp":{}}}}]`)
	if hp := dockerHostPorts(jExpose, false); len(hp) != 0 {
		t.Fatalf("dockerHostPorts(expose-only) = %v, want []", hp)
	}
}

func TestParseNginxListenPorts(t *testing.T) {
	cfg := `
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name app.example.com;
    location / { proxy_pass http://127.0.0.1:3000; }
}
server {
    listen 443 ssl;
    listen [::]:443 ssl;
}
`
	ports := parseNginxListenPorts(cfg)
	if len(ports) != 2 || ports[0] != 80 || ports[1] != 443 {
		t.Fatalf("got %v, want [80 443]", ports)
	}
	if p, err := pickPublicHTTPPort(ports); err != nil || p != 80 {
		t.Fatalf("pickPublicHTTPPort = %d,%v; want 80", p, err)
	}
	if p, _ := pickPublicHTTPPort([]int{8080, 443}); p != 8080 {
		t.Fatalf("non-80 pick = %d; want 8080", p)
	}
	if _, err := pickPublicHTTPPort([]int{443}); err == nil {
		t.Fatal("expected error when only 443 present")
	}
}

func TestIsPrivateIP(t *testing.T) {
	priv := []string{"10.45.175.254", "192.168.1.10", "172.16.0.5", "127.0.0.1", "169.254.1.1", "100.64.0.1", "0.0.0.0", "garbage"}
	pub := []string{"103.189.235.184", "8.8.8.8", "1.1.1.1", "203.0.113.9"}
	for _, ip := range priv {
		if !isPrivateIP(ip) {
			t.Errorf("isPrivateIP(%q) = false, want true", ip)
		}
	}
	for _, ip := range pub {
		if isPrivateIP(ip) {
			t.Errorf("isPrivateIP(%q) = true, want false", ip)
		}
	}
}

func TestSanitizeName(t *testing.T) {
	cases := map[string]string{
		"my-app":          "my-app",
		"/etc/x/app.conf": "etc-x-app.conf",
		"App Name!":       "App-Name",
		"...weird..":      "weird",
	}
	for in, want := range cases {
		if got := sanitizeName(in); got != want {
			t.Errorf("sanitizeName(%q)=%q want %q", in, got, want)
		}
	}
}
