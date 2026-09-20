package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Duration struct {
	time.Duration
}

func (d *Duration) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return errors.New("duration must be a string such as \"10s\"")
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", value, err)
	}
	d.Duration = parsed
	return nil
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

type Config struct {
	Server   ServerConfig   `json:"server"`
	Upstream UpstreamConfig `json:"upstream"`
	WAF      WAFConfig      `json:"waf"`
	Logging  LoggingConfig  `json:"logging"`
}

type ServerConfig struct {
	ListenAddress     string   `json:"listen_address"`
	ReadHeaderTimeout Duration `json:"read_header_timeout"`
	ReadTimeout       Duration `json:"read_timeout"`
	WriteTimeout      Duration `json:"write_timeout"`
	IdleTimeout       Duration `json:"idle_timeout"`
	ShutdownTimeout   Duration `json:"shutdown_timeout"`
}

type UpstreamConfig struct {
	URL                   string `json:"url"`
	PreserveHost          bool   `json:"preserve_host"`
	TrustForwardedHeaders bool   `json:"trust_forwarded_headers"`
}

type WAFConfig struct {
	Mode              string      `json:"mode"`
	MaxBodyBytes      int64       `json:"max_body_bytes"`
	MaxDecodePasses   int         `json:"max_decode_passes"`
	BlockStatus       int         `json:"block_status"`
	InspectMethods    []string    `json:"inspect_methods"`
	EnabledCategories []string    `json:"enabled_categories"`
	Exclusions        []Exclusion `json:"exclusions"`
}

type Exclusion struct {
	PathPrefix string   `json:"path_prefix"`
	Methods    []string `json:"methods"`
	Parameters []string `json:"parameters"`
	Categories []string `json:"categories"`
}

type LoggingConfig struct {
	Level string `json:"level"`
}

func Default() Config {
	return Config{
		Server: ServerConfig{
			ListenAddress:     "127.0.0.1:8081",
			ReadHeaderTimeout: Duration{5 * time.Second},
			ReadTimeout:       Duration{30 * time.Second},
			WriteTimeout:      Duration{60 * time.Second},
			IdleTimeout:       Duration{90 * time.Second},
			ShutdownTimeout:   Duration{10 * time.Second},
		},
		Upstream: UpstreamConfig{URL: "http://127.0.0.1:8080"},
		WAF: WAFConfig{
			Mode:              "block",
			MaxBodyBytes:      1 << 20,
			MaxDecodePasses:   3,
			BlockStatus:       403,
			InspectMethods:    []string{"POST", "PUT", "PATCH"},
			EnabledCategories: []string{"lfi", "sqli", "xss"},
		},
		Logging: LoggingConfig{Level: "info"},
	}
}

func Load(path string) (Config, error) {
	cfg := Default()
	if path != "" {
		file, err := os.Open(path)
		if err != nil {
			return Config{}, fmt.Errorf("open config: %w", err)
		}
		defer file.Close()

		decoder := json.NewDecoder(io.LimitReader(file, 1<<20))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&cfg); err != nil {
			return Config{}, fmt.Errorf("decode config: %w", err)
		}
		if decoder.Decode(&struct{}{}) != io.EOF {
			return Config{}, errors.New("decode config: trailing JSON data")
		}
	}
	if err := applyEnvironment(&cfg); err != nil {
		return Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func applyEnvironment(cfg *Config) error {
	if value := os.Getenv("MINIMAL_WAF_LISTEN_ADDRESS"); value != "" {
		cfg.Server.ListenAddress = value
	}
	if value := os.Getenv("MINIMAL_WAF_UPSTREAM_URL"); value != "" {
		cfg.Upstream.URL = value
	}
	if value := os.Getenv("MINIMAL_WAF_MODE"); value != "" {
		cfg.WAF.Mode = strings.ToLower(value)
	}
	if value := os.Getenv("MINIMAL_WAF_MAX_BODY_BYTES"); value != "" {
		parsed, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return fmt.Errorf("MINIMAL_WAF_MAX_BODY_BYTES: %w", err)
		}
		cfg.WAF.MaxBodyBytes = parsed
	}
	return nil
}

func (c Config) Validate() error {
	if c.Server.ListenAddress == "" {
		return errors.New("server.listen_address is required")
	}
	upstream, err := url.Parse(c.Upstream.URL)
	if err != nil || upstream.Scheme == "" || upstream.Host == "" {
		return errors.New("upstream.url must be an absolute HTTP or HTTPS URL")
	}
	if upstream.Scheme != "http" && upstream.Scheme != "https" {
		return errors.New("upstream.url scheme must be http or https")
	}
	if c.WAF.Mode != "block" && c.WAF.Mode != "monitor" {
		return errors.New("waf.mode must be block or monitor")
	}
	if c.WAF.MaxBodyBytes < 1 || c.WAF.MaxBodyBytes > 100<<20 {
		return errors.New("waf.max_body_bytes must be between 1 byte and 100 MiB")
	}
	if c.WAF.MaxDecodePasses < 1 || c.WAF.MaxDecodePasses > 8 {
		return errors.New("waf.max_decode_passes must be between 1 and 8")
	}
	if c.WAF.BlockStatus < 400 || c.WAF.BlockStatus > 499 {
		return errors.New("waf.block_status must be a 4xx status")
	}
	validCategories := map[string]bool{"lfi": true, "sqli": true, "xss": true}
	for _, category := range c.WAF.EnabledCategories {
		if !validCategories[strings.ToLower(category)] {
			return fmt.Errorf("unsupported WAF category %q", category)
		}
	}
	for i, exclusion := range c.WAF.Exclusions {
		if exclusion.PathPrefix == "" || exclusion.PathPrefix[0] != '/' {
			return fmt.Errorf("waf.exclusions[%d].path_prefix must begin with /", i)
		}
	}
	return nil
}
