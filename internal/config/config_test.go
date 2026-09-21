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

func TestLoggingDefaults(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Logging.FilePath != "" || cfg.Logging.MaxSizeMB != 10 || cfg.Logging.MaxBackups != 5 || cfg.Logging.MaxAgeDays != 30 || !cfg.Logging.Compress {
		t.Fatalf("unexpected logging defaults: %#v", cfg.Logging)
	}
}

func TestLoggingFileConfig(t *testing.T) {
	cfg := Default()
	cfg.Logging.FilePath = filepath.Join(t.TempDir(), "waf.jsonl")
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		modify func(*LoggingConfig)
	}{
		{"relative path", func(c *LoggingConfig) { c.FilePath = "waf.jsonl" }},
		{"zero size", func(c *LoggingConfig) { c.MaxSizeMB = 0 }},
		{"excessive size", func(c *LoggingConfig) { c.MaxSizeMB = 1025 }},
		{"negative backups", func(c *LoggingConfig) { c.MaxBackups = -1 }},
		{"negative age", func(c *LoggingConfig) { c.MaxAgeDays = -1 }},
		{"unbounded backups", func(c *LoggingConfig) { c.MaxBackups, c.MaxAgeDays = 0, 0 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			invalid := cfg
			test.modify(&invalid.Logging)
			if err := invalid.Validate(); err == nil {
				t.Fatal("expected invalid logging configuration to fail")
			}
		})
	}
}
