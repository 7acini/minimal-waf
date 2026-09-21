package logging

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/7acini/minimal-waf/internal/config"
)

func TestStdoutOnly(t *testing.T) {
	cfg := config.Default().Logging
	var output bytes.Buffer
	logger, closer, err := New(cfg, &output)
	if err != nil {
		t.Fatal(err)
	}
	if closer != nil {
		t.Fatal("stdout-only logger must not return a file")
	}
	logger.Info("started", "request_id", "test-1")
	var entry map[string]any
	if err := json.Unmarshal(output.Bytes(), &entry); err != nil {
		t.Fatal(err)
	}
	if entry["msg"] != "started" || entry["request_id"] != "test-1" {
		t.Fatalf("unexpected log entry: %#v", entry)
	}
}

func TestWritesJSONToStdoutAndFile(t *testing.T) {
	cfg := config.Default().Logging
	cfg.FilePath = filepath.Join(t.TempDir(), "logs", "waf.jsonl")
	var output bytes.Buffer
	logger, closer, err := New(cfg, &output)
	if err != nil {
		t.Fatal(err)
	}
	logger.Warn("WAF detection", "rule_ids", []string{"LFI-001"})
	if err := closer.Close(); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(cfg.FilePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(output.Bytes(), content) {
		t.Fatal("stdout and file logs differ")
	}
	var entry map[string]any
	if err := json.Unmarshal(content, &entry); err != nil {
		t.Fatal(err)
	}
	if entry["msg"] != "WAF detection" {
		t.Fatalf("unexpected entry: %#v", entry)
	}
	info, err := os.Stat(cfg.FilePath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("log file mode = %o, want 600", info.Mode().Perm())
	}
}

func TestRotatesBySize(t *testing.T) {
	cfg := config.Default().Logging
	cfg.FilePath = filepath.Join(t.TempDir(), "waf.jsonl")
	cfg.MaxSizeMB = 1
	cfg.Compress = false
	logger, closer, err := New(cfg, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	for range 10 {
		logger.Info("large event", "marker", strings.Repeat("x", 128*1024))
	}
	if err := closer.Close(); err != nil {
		t.Fatal(err)
	}
	backups, err := filepath.Glob(filepath.Join(filepath.Dir(cfg.FilePath), "waf-*.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if len(backups) == 0 {
		t.Fatal("expected at least one rotated backup")
	}
	if _, err := os.Stat(cfg.FilePath); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentWrites(t *testing.T) {
	cfg := config.Default().Logging
	cfg.FilePath = filepath.Join(t.TempDir(), "waf.jsonl")
	logger, closer, err := New(cfg, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	const workers, entriesPerWorker = 16, 25
	var group sync.WaitGroup
	for worker := range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			for range entriesPerWorker {
				logger.Info("concurrent event", "worker", worker)
			}
		}()
	}
	group.Wait()
	if err := closer.Close(); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(cfg.FilePath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	count := 0
	for scanner.Scan() {
		var entry map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			t.Fatal(err)
		}
		count++
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if count != workers*entriesPerWorker {
		t.Fatalf("wrote %d entries, want %d", count, workers*entriesPerWorker)
	}
}

func TestRejectsUnwritableLogPath(t *testing.T) {
	cfg := config.Default().Logging
	cfg.FilePath = t.TempDir()
	if _, _, err := New(cfg, io.Discard); err == nil {
		t.Fatal("expected logger initialization to fail for a directory path")
	}
	if info, err := os.Stat(cfg.FilePath); err != nil || !info.IsDir() {
		t.Fatalf("directory was changed by logger initialization: info=%v err=%v", info, err)
	}
}

func TestRejectsSymlinkAndPermissiveFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "waf.jsonl")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default().Logging
	cfg.FilePath = path
	if _, _, err := New(cfg, io.Discard); err == nil {
		t.Fatal("expected permissive file to be rejected")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(filepath.Dir(path), "link.jsonl")
	if err := os.Symlink(path, symlink); err != nil {
		t.Fatal(err)
	}
	cfg.FilePath = symlink
	if _, _, err := New(cfg, io.Discard); err == nil {
		t.Fatal("expected symlink to be rejected")
	}
}

func TestFileWriteFailurePreservesStdout(t *testing.T) {
	var stdout, diagnostics bytes.Buffer
	writer := mirroredWriter{
		stdout: &stdout,
		file:   failingWriter{},
		errors: &diagnostics,
	}
	message := []byte(`{"msg":"safe"}` + "\n")
	if n, err := writer.Write(message); err != nil || n != len(message) {
		t.Fatalf("write = (%d, %v), want (%d, nil)", n, err, len(message))
	}
	if !bytes.Equal(stdout.Bytes(), message) {
		t.Fatal("stdout copy was lost")
	}
	if !strings.Contains(diagnostics.String(), "rotating log write failed") || strings.Contains(diagnostics.String(), `"safe"`) {
		t.Fatalf("unexpected file error diagnostic: %q", diagnostics.String())
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("disk unavailable")
}
