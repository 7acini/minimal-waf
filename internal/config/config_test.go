package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.WAF.Mode != "block" || cfg.Upstream.URL == "" || cfg.WAF.MaxBodyBytes == 0 {
		t.Fatalf("unexpected defaults: %#v", cfg)
	}
}

func TestLoadFileAndEnvironmentOverride(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "config.json")
	data := `{
  "server": {"listen_address":"127.0.0.1:9000"},
  "upstream": {"url":"http://127.0.0.1:8080"},
  "waf": {"mode":"monitor","max_body_bytes":1024,"max_decode_passes":2,"block_status":403,"inspect_methods":["POST"],"enabled_categories":["lfi"]}
}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MINIMAL_WAF_MODE", "block")
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.WAF.Mode != "block" || cfg.Server.ListenAddress != "127.0.0.1:9000" {
		t.Fatalf("unexpected config: %#v", cfg)
	}
}

func TestRejectsUnknownField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"unknown":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error for unknown field")
	}
}
