// Package config memuat dan memvalidasi konfigurasi ExactusWAF dari file YAML.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config adalah seluruh isi config.yaml.
type Config struct {
	Listen    string          `yaml:"listen"`
	Backend   string          `yaml:"backend"`
	Mode      string          `yaml:"mode"`
	Dashboard DashboardConfig `yaml:"dashboard"`
	RateLimit RateLimitConfig `yaml:"rate_limit"`
	IPBlock   []string        `yaml:"ip_blocklist"`
	IPAllow   []string        `yaml:"ip_allowlist"`
	TLS               TLSConfig     `yaml:"tls"`
	AutoBan           AutoBanConfig `yaml:"auto_ban"`
	Notify            NotifyConfig  `yaml:"notify"`
	TrustProxyHeaders bool          `yaml:"trust_proxy_headers"`
	RulesFile         string        `yaml:"rules_file"`
	LogFile           string        `yaml:"log_file"`
}

type DashboardConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Listen   string `yaml:"listen"`
	Password string `yaml:"password"`
}

type RateLimitConfig struct {
	Enabled           bool `yaml:"enabled"`
	RequestsPerMinute int  `yaml:"requests_per_minute"`
	Burst             int  `yaml:"burst"`
}

type TLSConfig struct {
	Enabled  bool   `yaml:"enabled"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// AutoBanConfig: blokir sementara IP yang menyerang berulang.
type AutoBanConfig struct {
	Enabled       bool   `yaml:"enabled"`
	MaxStrikes    int    `yaml:"max_strikes"`
	WindowMinutes int    `yaml:"window_minutes"`
	BanMinutes    int    `yaml:"ban_minutes"`
	Scope         string `yaml:"scope"` // "ip" atau "ip_ua"
}

// NotifyConfig: pemberitahuan saat ada serangan.
type NotifyConfig struct {
	Telegram TelegramConfig `yaml:"telegram"`
}

type TelegramConfig struct {
	Enabled  bool   `yaml:"enabled"`
	BotToken string `yaml:"bot_token"`
	ChatID   string `yaml:"chat_id"`
}

// Load membaca file konfigurasi dan mengembalikan Config yang sudah divalidasi.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("tidak bisa membaca file konfigurasi %q: %w", path, err)
	}

	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("format config.yaml tidak valid: %w", err)
	}

	c.applyDefaults()
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) applyDefaults() {
	if c.Listen == "" {
		c.Listen = "0.0.0.0:8080"
	}
	if c.Mode == "" {
		c.Mode = "block"
	}
	if c.RateLimit.Enabled {
		if c.RateLimit.RequestsPerMinute <= 0 {
			c.RateLimit.RequestsPerMinute = 120
		}
		if c.RateLimit.Burst <= 0 {
			c.RateLimit.Burst = 30
		}
	}
	if c.Dashboard.Enabled && c.Dashboard.Listen == "" {
		c.Dashboard.Listen = "127.0.0.1:9090"
	}
	if c.AutoBan.Enabled {
		if c.AutoBan.MaxStrikes <= 0 {
			c.AutoBan.MaxStrikes = 5
		}
		if c.AutoBan.WindowMinutes <= 0 {
			c.AutoBan.WindowMinutes = 10
		}
		if c.AutoBan.BanMinutes <= 0 {
			c.AutoBan.BanMinutes = 60
		}
		if c.AutoBan.Scope != "ip" && c.AutoBan.Scope != "ip_ua" {
			// Default aman untuk IP bersama (CGNAT / ISP seluler seperti Telkomsel):
			// sertakan sidik jari User-Agent agar ban tidak menyeret pengguna lain
			// yang kebetulan berbagi IP publik yang sama.
			c.AutoBan.Scope = "ip_ua"
		}
	}
}

func (c *Config) validate() error {
	if c.Backend == "" {
		return fmt.Errorf("field 'backend' wajib diisi (alamat website asli Anda, mis. http://127.0.0.1:3000)")
	}
	if c.Mode != "block" && c.Mode != "monitor" {
		return fmt.Errorf("field 'mode' harus 'block' atau 'monitor', bukan %q", c.Mode)
	}
	if c.TLS.Enabled && (c.TLS.CertFile == "" || c.TLS.KeyFile == "") {
		return fmt.Errorf("tls diaktifkan tapi cert_file/key_file kosong")
	}
	return nil
}
