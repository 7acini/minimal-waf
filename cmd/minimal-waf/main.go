package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/7acini/minimal-waf/internal/config"
	"github.com/7acini/minimal-waf/internal/logging"
	"github.com/7acini/minimal-waf/internal/waf"
)

var version = "dev"

func main() {
	os.Exit(run())
}

func run() int {
	configPath := flag.String("config", "config.json", "path to the JSON configuration file")
	checkConfig := flag.Bool("check-config", false, "validate configuration and exit")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return 0
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "configuration error: %v\n", err)
		return 1
	}
	if *checkConfig {
		fmt.Println("configuration is valid")
		return 0
	}

	logger, logFile, err := logging.New(cfg.Logging, os.Stdout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "logging error: %v\n", err)
		return 1
	}
	if logFile != nil {
		defer logFile.Close()
	}
	handler, err := waf.NewHandler(cfg, logger)
	if err != nil {
		logger.Error("unable to create WAF", "error", err)
		return 1
	}
	server := &http.Server{
		Addr:              cfg.Server.ListenAddress,
		Handler:           handler,
		ReadHeaderTimeout: cfg.Server.ReadHeaderTimeout.Duration,
		ReadTimeout:       cfg.Server.ReadTimeout.Duration,
		WriteTimeout:      cfg.Server.WriteTimeout.Duration,
		IdleTimeout:       cfg.Server.IdleTimeout.Duration,
	}

	shutdownSignal, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	serveDone := make(chan struct{})
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		select {
		case <-shutdownSignal.Done():
			shutdownContext, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout.Duration)
			defer cancel()
			if err := server.Shutdown(shutdownContext); err != nil {
				logger.Error("graceful shutdown failed", "error", err)
			}
		case <-serveDone:
		}
	}()

	logger.Info("minimal-waf started", "version", version, "listen_address", cfg.Server.ListenAddress, "mode", cfg.WAF.Mode)
	serveErr := server.ListenAndServe()
	close(serveDone)
	<-shutdownDone
	if serveErr != nil && serveErr != http.ErrServerClosed {
		logger.Error("server stopped unexpectedly", "error", serveErr)
		return 1
	}
	logger.Info("minimal-waf stopped")
	return 0
}
