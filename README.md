<div align="center">

# minimal-waf

### Ship fast. Keep your backend behind a security checkpoint you can actually read.

A tiny, container-ready Web Application Firewall built in Go for legacy PHP,
indie SaaS, and the new wave of AI-assisted applications.

[![CI](https://github.com/7acini/minimal-waf/actions/workflows/ci.yml/badge.svg)](https://github.com/7acini/minimal-waf/actions/workflows/ci.yml)
[![Go 1.24+](https://img.shields.io/badge/Go-1.24%2B-00ADD8?logo=go&logoColor=white)](go.mod)
[![stdlib only](https://img.shields.io/badge/dependencies-stdlib%20only-2ea44f)](go.mod)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**One binary · One config · Zero runtime dependencies · No TLS ceremony**

</div>

---

Software can now go from idea to production in a weekend. The security boundary
still deserves to be explicit.

`minimal-waf` sits between your public Apache or Nginx and your private
application server. It normalizes and inspects hostile input before it reaches
PHP, while keeping the deployment small enough for one person to understand,
test, and operate.

It is not a security platform, an appliance, or a cloud subscription. It is a
focused reverse proxy with a deliberately small attack surface.

## Why minimal-waf?

- **Built for small teams.** A readable codebase, a JSON config, and useful
  defaults instead of a rule engine that needs its own operations team.
- **Container-shaped by design.** Static binary, `scratch` image, non-root user,
  read-only configuration, JSON logs, health checks, metrics, and graceful
  shutdown.
- **Friendly to existing stacks.** Keep Apache/PHP today and move the public
  edge to Nginx later without changing the WAF contract.
- **Safe rollout.** Observe real traffic in `monitor`, tune narrow exclusions,
  then move to `block`.
- **No dependency maze.** The Go runtime uses only the standard library.
- **Honest security.** This is a defense-in-depth control, not a substitute for
  fixing vulnerabilities in the application.

## The 30-second architecture

```text
                         public edge                  private network

  Internet  ─────▶  Apache or Nginx  ─────▶  minimal-waf  ─────▶  Apache/PHP
                         TLS :443              HTTP :8081          HTTP :8080
```

TLS stays at the public proxy. The WAF and the application backend can listen
on loopback or a private container network. The backend must not be publicly
reachable, otherwise clients can bypass the WAF entirely.

The same topology works for any HTTP backend; PHP is the primary threat model
and deployment target.

## What it catches

The built-in rules currently cover:

| Category | Examples |
|---|---|
| LFI / path traversal | `../`, sensitive Unix and Windows paths, PHP stream wrappers |
| SQL injection | UNION, boolean tautologies, time-based payloads, stacked destructive statements, metadata access |
| Cross-site scripting | script tags, inline event handlers, JavaScript URIs, HTML data URIs, CSS expressions |

Inspection applies to URL paths, query names and values, URL-encoded forms,
nested JSON objects and arrays, multipart text fields and filenames, and textual
`POST`, `PUT`, and `PATCH` bodies.

Normalization is bounded and handles percent encoding, repeated encoding, HTML
entities, backslashes, null bytes, and letter case. Multipart file contents are
never treated as text; only filenames and regular text fields are inspected.

## Quick start

### Run as a Go binary

Requirements: Go 1.24 or newer and an HTTP backend listening on a private or
loopback address.

```bash
cp config.example.json config.json
go test ./...
make build
./bin/minimal-waf -config ./config.json
```

The example listens on `127.0.0.1:8081`, proxies to
`http://127.0.0.1:8080`, and starts in `monitor` mode.

Validate a configuration without opening a listener:

```bash
./bin/minimal-waf -config ./config.json -check-config
```

### Run as a hardened container

Build the tiny `scratch` image locally:

```bash
cp config.example.json config.json
docker build --build-arg VERSION=dev -t minimal-waf:local .
docker run --rm --name minimal-waf \
  --network host \
  --read-only \
  --cap-drop ALL \
  -v "$PWD/config.json:/etc/minimal-waf/config.json:ro" \
  minimal-waf:local
```

The host-network example is intended for Linux hosts where the public proxy and
private backend already use loopback. In a multi-container setup, attach the
edge proxy, WAF, and backend to the same private network, set the WAF listener
to `0.0.0.0:8081` inside that network, and publish only the edge proxy.

## Start in monitor. Earn your way to block.

The two modes intentionally have different failure behavior:

| Behavior | `monitor` | `block` |
|---|---:|---:|
| Log signature detections | yes | yes |
| Forward a detected request | yes | no |
| Oversized inspectable body | forward intact, skip inspection, log | reject with `413` |
| Block response | n/a | configurable `4xx` plus request ID |

Start with `"mode": "monitor"`, observe legitimate production traffic, add
only narrow and auditable exclusions, then switch to `block`. A blocked request
never reaches the upstream application.

## Configuration

The complete starting point lives in
[`config.example.json`](config.example.json).

| Field | Purpose |
|---|---|
| `server.listen_address` | Gateway address; prefer loopback when Apache/Nginx runs on the host |
| `server.*_timeout` | Explicit server and shutdown timeouts |
| `upstream.url` | Absolute URL of the private application backend |
| `upstream.preserve_host` | Preserve the original Host for backend virtual hosts |
| `upstream.trust_forwarded_headers` | Trust the incoming proxy chain only on a restricted listener |
| `waf.mode` | `monitor` or `block` |
| `waf.max_body_bytes` | Maximum body buffered and inspected per request |
| `waf.max_decode_passes` | Bounded repeated-decoding passes |
| `waf.block_status` | Configurable `4xx` response in block mode |
| `waf.inspect_methods` | HTTP methods whose bodies are inspected |
| `waf.enabled_categories` | Any combination of `lfi`, `sqli`, and `xss` |
| `waf.exclusions` | Granular exceptions by route, method, parameter, and category |

Common settings can also be overridden at deployment time:

```bash
export MINIMAL_WAF_LISTEN_ADDRESS=127.0.0.1:8081
export MINIMAL_WAF_UPSTREAM_URL=http://127.0.0.1:8080
export MINIMAL_WAF_MODE=monitor
export MINIMAL_WAF_MAX_BODY_BYTES=1048576
```

### Forwarded headers: choose a trust boundary

If the WAF listener accepts traffic **only** from a trusted Apache or Nginx,
`trust_forwarded_headers` may be enabled to preserve the proxy chain. Restrict
that listener with loopback, a private network, or firewall rules.

If clients can reach the WAF directly, disable it. The WAF then removes
client-supplied `Forwarded` and `X-Forwarded-*` headers before generating trusted
proxy values. Never trust an internet-supplied `X-Forwarded-For` chain.

### Keep exclusions surgical

This example suppresses SQLi detection only for one parameter, method, route,
and category:

```json
{
  "path_prefix": "/admin/report/search",
  "methods": ["POST"],
  "parameters": ["query"],
  "categories": ["sqli"]
}
```

Add it to `waf.exclusions`. An empty array means “any value” on that axis and
therefore creates a broader security exception.

## Put it in front of your app

### Apache today

1. Bind the PHP backend to `127.0.0.1:8080` using
   [`deploy/apache/backend-vhost.conf`](deploy/apache/backend-vhost.conf).
2. Route the public TLS virtual host to the WAF using
   [`deploy/apache/public-vhost.conf`](deploy/apache/public-vhost.conf).
3. Validate before reloading:

```bash
sudo a2enmod proxy proxy_http headers ssl rewrite
sudo apachectl configtest
sudo systemctl reload apache2
```

### Nginx tomorrow

Use [`deploy/nginx/minimal-waf.conf`](deploy/nginx/minimal-waf.conf) as the edge
configuration. Nginx terminates TLS, the WAF inspects HTTP, and Apache/PHP stays
private. Keep `client_max_body_size` aligned with your intended WAF limit so the
edge behavior is predictable.

### systemd without containers

```bash
sudo install -o root -g root -m 0755 bin/minimal-waf /usr/local/bin/minimal-waf
sudo useradd --system --home /nonexistent --shell /usr/sbin/nologin minimal-waf
sudo install -d -o root -g minimal-waf -m 0750 /etc/minimal-waf
sudo install -o root -g minimal-waf -m 0640 config.json /etc/minimal-waf/config.json
sudo install -o root -g root -m 0644 deploy/systemd/minimal-waf.service /etc/systemd/system/minimal-waf.service
sudo systemctl daemon-reload
sudo systemctl enable --now minimal-waf
```

The supplied unit includes systemd hardening and grants no Linux capabilities.

## Operate it

| Endpoint / signal | Behavior |
|---|---|
| `GET /_minimal-waf/healthz` | Lightweight JSON liveness response |
| `GET /_minimal-waf/metrics` | Prometheus-compatible counters |
| `SIGINT` / `SIGTERM` | Graceful shutdown within the configured timeout |
| stdout | Structured JSON operational and detection logs |

Operational endpoints are handled by the WAF and are never proxied to the
application. Do not expose `/_minimal-waf/` publicly; the Apache and Nginx
examples deny that prefix at the edge.

Detection logs contain request ID, mode, method, path, client IP, rule IDs,
categories, locations, and parameter names. They do **not** include cookies,
authorization headers, full bodies, or complete parameter values.

## Verify the boundary

Use these requests only against an environment you control:

```bash
curl --path-as-is -i \
  'https://legacy.example.com/index.php?e=../../../../etc/passwd'

curl -i -X POST 'https://legacy.example.com/index.php' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'e=../../../../etc/hosts'

curl -i -X POST 'https://legacy.example.com/api/search' \
  -H 'Content-Type: application/json' \
  --data '{"q":"<img src=x onerror=alert(1)>"}'
```

In `block` mode, each response should be a `4xx` with a request ID and the
private backend should receive no corresponding request.

## Security boundaries

`minimal-waf` intentionally does a small number of things well. Keep these
limits visible:

- Signature detection can produce false positives and can be bypassed.
- Uploaded file contents are not scanned; filenames and text fields are.
- TLS termination belongs to Apache, Nginx, or another trusted edge proxy.
- The project does not replace patching, authentication, authorization, rate
  limiting, CSP, SAST/DAST, or application-specific validation.
- A private backend is part of the security model, not an optional hardening
  step.

For exploitable bypasses or vulnerabilities, follow
[`SECURITY.md`](SECURITY.md) and use GitHub's private vulnerability reporting.

## Build, test, contribute

The repository keeps the contributor loop intentionally short:

```bash
gofmt -w .
go vet ./...
go test -race ./...
CGO_ENABLED=0 go build -trimpath ./cmd/minimal-waf
```

Rules should have stable IDs, RE2-compatible patterns, malicious regression
cases, and similar benign cases. Prefer narrow changes, standard-library
solutions, and commits in the form `type(scope): description`.

If you are building fast—alone, with a small team, or with AI—this project is
meant to stay understandable enough that you can own the entire path from
request to backend.

MIT licensed. Small enough to audit. Useful enough to keep in the path.
