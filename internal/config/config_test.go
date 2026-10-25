package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Dashboard tanpa password tidak boleh menjatuhkan seluruh WAF; cukup dashboard
// yang dimatikan sambil memberi peringatan, agar situs tetap terlindungi.
func TestDashboardTanpaPasswordDimatikanBukanError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	yaml := "backend: \"http://127.0.0.1:3000\"\ndashboard:\n  enabled: true\n  password: \"\"\n"
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("WAF seharusnya tetap jalan, tapi gagal: %v", err)
	}
	if c.Dashboard.Enabled {
		t.Fatal("dashboard harus dimatikan saat password kosong")
	}
	if len(c.Warnings) == 0 || !strings.Contains(strings.Join(c.Warnings, " "), "password") {
		t.Fatalf("harus ada peringatan soal password, dapat %v", c.Warnings)
	}
}
