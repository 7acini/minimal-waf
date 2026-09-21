package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/7acini/minimal-waf/internal/config"
	"gopkg.in/natefinch/lumberjack.v2"
)

// New writes JSON logs to output and, when configured, to a rotating file.
// The returned closer must be called after the last log message.
func New(cfg config.LoggingConfig, output io.Writer) (*slog.Logger, io.Closer, error) {
	var destination io.Writer = output
	var file io.Closer
	if cfg.FilePath != "" {
		if info, err := os.Lstat(cfg.FilePath); err == nil {
			if !info.Mode().IsRegular() {
				return nil, nil, fmt.Errorf("log path is not a regular file: %s", cfg.FilePath)
			}
			if info.Mode().Perm()&0o077 != 0 {
				return nil, nil, fmt.Errorf("log file permissions must not allow group or other access: %s", cfg.FilePath)
			}
		} else if !os.IsNotExist(err) {
			return nil, nil, fmt.Errorf("inspect log file: %w", err)
		}
		rotating := &lumberjack.Logger{
			Filename:   cfg.FilePath,
			MaxSize:    cfg.MaxSizeMB,
			MaxBackups: cfg.MaxBackups,
			MaxAge:     cfg.MaxAgeDays,
			Compress:   cfg.Compress,
		}
		// Lumberjack opens the file on first Write. Check access at startup so
		// an unwritable path cannot silently discard file logs later.
		if _, err := rotating.Write(nil); err != nil {
			_ = rotating.Close()
			return nil, nil, fmt.Errorf("open rotating log file: %w", err)
		}
		destination = mirroredWriter{stdout: output, file: rotating, errors: os.Stderr}
		file = rotating
	}
	logger := slog.New(slog.NewJSONHandler(destination, &slog.HandlerOptions{Level: logLevel(cfg.Level)}))
	return logger, file, nil
}

// mirroredWriter preserves stdout logging even when a rotating file fails.
// slog intentionally does not expose Handler write errors, so also report a
// file failure directly to stderr without repeating the log payload.
type mirroredWriter struct {
	stdout io.Writer
	file   io.Writer
	errors io.Writer
}

func (writer mirroredWriter) Write(payload []byte) (int, error) {
	_, fileErr := writer.file.Write(payload)
	stdoutCount, stdoutErr := writer.stdout.Write(payload)
	if fileErr != nil {
		_, _ = fmt.Fprintf(writer.errors, "rotating log write failed: %v\n", fileErr)
	}
	if stdoutErr != nil {
		return stdoutCount, stdoutErr
	}
	return len(payload), nil
}

func logLevel(value string) slog.Level {
	switch strings.ToLower(value) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
