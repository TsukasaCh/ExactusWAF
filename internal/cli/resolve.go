package cli

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// normalizeBackend turns a user target like "http://x", "host:port", ":port" or
// "port" into a proper backend URL. Pure function (easy to test).
func normalizeBackend(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf("empty backend")
	}
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		return strings.TrimRight(s, "/"), nil
	}
	host, port := "127.0.0.1", s
	if i := strings.LastIndex(s, ":"); i >= 0 {
		if s[:i] != "" {
			host = s[:i]
		}
		port = s[i+1:]
	}
	if port == "" || !isAllDigits(port) {
		return "", fmt.Errorf("cannot understand target %q (use http://host:port, host:port, or a port)", s)
	}
	return "http://" + host + ":" + port, nil
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// ---- Docker ----

type dockerInspect struct {
	Name            string `json:"Name"`
	NetworkSettings struct {
		IPAddress string `json:"IPAddress"`
		Networks  map[string]struct {
			IPAddress string `json:"IPAddress"`
		} `json:"Networks"`
		Ports map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"Ports"`
	} `json:"NetworkSettings"`
	Config struct {
		ExposedPorts map[string]struct{} `json:"ExposedPorts"`
	} `json:"Config"`
}

// parseDockerInspect extracts the container IP and the best web port from the
// JSON array returned by `docker inspect`. Pure function (testable with fixtures).
func parseDockerInspect(data []byte, portOverride int) (ip string, port int, err error) {
	var arr []dockerInspect
	if err := json.Unmarshal(data, &arr); err != nil || len(arr) == 0 {
		return "", 0, fmt.Errorf("could not read docker inspect output")
	}
	c := arr[0]
	ip = c.NetworkSettings.IPAddress
	if ip == "" {
		for _, n := range c.NetworkSettings.Networks {
			if n.IPAddress != "" {
				ip = n.IPAddress
				break
			}
		}
	}
	if ip == "" {
		return "", 0, fmt.Errorf("container has no IP address (is it running?)")
	}
	if portOverride > 0 {
		return ip, portOverride, nil
	}
	// Collect candidate tcp ports from ExposedPorts + Ports, pick the smallest.
	seen := map[int]bool{}
	for p := range c.Config.ExposedPorts {
		if n := tcpPort(p); n > 0 {
			seen[n] = true
		}
	}
	for p := range c.NetworkSettings.Ports {
		if n := tcpPort(p); n > 0 {
			seen[n] = true
		}
	}
	if len(seen) == 0 {
		return "", 0, fmt.Errorf("container exposes no ports; pass --port <container-port>")
	}
	var ports []int
	for p := range seen {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ip, ports[0], nil
}

func tcpPort(spec string) int {
	// spec like "8080/tcp"
	if !strings.HasSuffix(spec, "/tcp") {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSuffix(spec, "/tcp"))
	if err != nil {
		return 0
	}
	return n
}

// dockerHostPorts returns the host ports the container publishes. publicOnly
// restricts to public interfaces (HostIp empty / 0.0.0.0 / ::); otherwise it
// returns every published host port (incl. 127.0.0.1). Pure function.
func dockerHostPorts(data []byte, publicOnly bool) []int {
	var arr []dockerInspect
	if json.Unmarshal(data, &arr) != nil || len(arr) == 0 {
		return nil
	}
	seen := map[int]bool{}
	var out []int
	for _, binds := range arr[0].NetworkSettings.Ports {
		for _, b := range binds {
			if b.HostPort == "" {
				continue
			}
			if publicOnly && !(b.HostIP == "" || b.HostIP == "0.0.0.0" || b.HostIP == "::") {
				continue
			}
			if n, err := strconv.Atoi(b.HostPort); err == nil && !seen[n] {
				seen[n] = true
				out = append(out, n)
			}
		}
	}
	sort.Ints(out)
	return out
}

func dockerPublicPorts(data []byte) []int { return dockerHostPorts(data, true) }

// resolveDocker inspects a container and returns its backend URL, name, the host
// ports it publishes publicly, and ALL host ports it publishes (any interface).
func resolveDocker(idOrName string, portOverride int) (backend, containerName string, publicPorts, hostPorts []int, err error) {
	out, err := exec.Command("docker", "inspect", idOrName).Output()
	if err != nil {
		return "", "", nil, nil, fmt.Errorf("docker inspect %q failed (is Docker installed and the container running?): %w", idOrName, err)
	}
	ip, port, err := parseDockerInspect(out, portOverride)
	if err != nil {
		return "", "", nil, nil, err
	}
	name := idOrName
	var arr []dockerInspect
	if json.Unmarshal(out, &arr) == nil && len(arr) > 0 {
		name = strings.TrimPrefix(arr[0].Name, "/")
	}
	return fmt.Sprintf("http://%s:%d", ip, port), name, dockerHostPorts(out, true), dockerHostPorts(out, false), nil
}

// ---- nginx config parsing ----

var reNginxListen = regexp.MustCompile(`(?m)^\s*listen\s+(?:(?:\[::\]|\*|[0-9.]+):)?(\d+)\b`)

// parseNginxListenPorts returns the ports a site config listens on. Pure.
func parseNginxListenPorts(cfg string) []int {
	var ports []int
	seen := map[int]bool{}
	for _, m := range reNginxListen.FindAllStringSubmatch(cfg, -1) {
		if n, err := strconv.Atoi(m[1]); err == nil && !seen[n] {
			seen[n] = true
			ports = append(ports, n)
		}
	}
	sort.Ints(ports)
	return ports
}

// pickPublicHTTPPort chooses which listen port ExactusWAF should take over:
// prefer 80, otherwise the lowest non-443 port.
func pickPublicHTTPPort(ports []int) (int, error) {
	for _, p := range ports {
		if p == 80 {
			return 80, nil
		}
	}
	for _, p := range ports {
		if p != 443 {
			return p, nil
		}
	}
	return 0, fmt.Errorf("no plain-HTTP listen port found (only 443?); ExactusWAF fronts HTTP")
}
