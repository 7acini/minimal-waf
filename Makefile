.PHONY: build test vet check

VERSION ?= dev

build:
	mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=$(VERSION)" -o bin/minimal-waf ./cmd/minimal-waf

test:
	go test -race ./...

vet:
	go vet ./...

check: vet test
