<div align="center">

# minimal-waf

### A small security gate for the apps you ship fast.

An open-source HTTP reverse proxy that inspects requests before they reach your
backend. One Go binary, a readable rule set, and a rollout you control.

[![CI](https://github.com/7acini/minimal-waf/actions/workflows/ci.yml/badge.svg)](https://github.com/7acini/minimal-waf/actions/workflows/ci.yml)
[![Go 1.24+](https://img.shields.io/badge/Go-1.24%2B-00ADD8?logo=go&logoColor=white)](go.mod)
[![MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![One Go dependency](https://img.shields.io/badge/Go%20dependencies-1-2ea44f)](go.mod)

**Framework-agnostic · Container-ready · Monitor first, block when ready**

[Try the local demo](#try-it-locally) ·
[See how it works](#how-it-works) ·
[Deploy it](#deploy) ·
[Understand the limits](#security-boundaries)

</div>

---

Shipping an app is faster than ever. Understanding what reaches it should be
just as easy.

`minimal-waf` gives solo builders and small teams a focused checkpoint between
the public edge and **any HTTP backend**—whether the app is written in Go,
JavaScript, Python, PHP, or something else. It catches selected patterns of
path traversal/LFI, SQL injection, and XSS; records what it sees; and can stop
a detected request before your application handles it.

No hosted control plane. No TLS stack inside the WAF. No mystery rule language.
Just a small component you can inspect, test, and replace.

## Try it locally

The repository includes a deliberately vulnerable sample app so you can see
both allowed and blocked traffic. The sample happens to use PHP; the WAF itself
speaks HTTP and does not depend on the backend language.

```bash
git clone https://github.com/7acini/minimal-waf.git
cd minimal-waf
docker compose -f demo/compose.yaml up --build -d
bash demo/smoke.sh
```

Open **<http://127.0.0.1:8088>**. Only the demo's Nginx edge is published, and
only on loopback. Try a normal search, then test a known attack pattern:

```bash
curl -i -G --data-urlencode 'file=../../../../etc/passwd' \
  http://127.0.0.1:8088/
```

The request should get `403` and `X-Request-ID`; the private application should
not receive it. The demo starts in `block` mode. See the
[lab guide](demo/README.md) for SQLi/XSS examples, logs, and cleanup.

> **Local lab only.** The sample application is intentionally vulnerable. Do
> not publish it or attach it to a production network.

## How it works

```text
    Client       public edge              security gate          private app
      │      ┌──────────────────┐     ┌─────────────────┐    ┌──────────────┐
      └─────▶│ Apache / Nginx   ├────▶│   minimal-waf   ├───▶│ HTTP backend │
             │ TLS termination  │     │ inspect + proxy │    │ any language │
             └──────────────────┘     └─────────────────┘    └──────────────┘
```

Your edge proxy keeps TLS. The WAF accepts HTTP from that proxy, inspects the
request, and forwards allowed traffic **with its original body**. The backend
should listen only on loopback or a private network; a publicly reachable
backend bypasses the WAF.

The inspection surface includes URL paths, query names and values, URL-encoded
forms, nested JSON, multipart text fields and filenames, and textual request
bodies on configured methods (`POST`, `PUT`, and `PATCH` by default). It does
**not** scan uploaded file contents as text.

Before matching signatures, the WAF applies bounded normalization for percent
encoding (including repeated encoding), HTML entities, backslashes, null
bytes, and case. Built-in rule IDs are stable and grouped by category:

| Category | Examples of patterns |
|---|---|
| `lfi` | Traversal sequences, sensitive file paths, stream wrappers |
| `sqli` | UNION queries, tautologies, time-based and stacked statements |
| `xss` | Script tags, event handlers, JavaScript and HTML data URIs |

These are **signatures**, not a proof that a request is safe. The complete
patterns and descriptions live in [rules.go](internal/waf/rules.go).

## Roll out without guessing

Start with `monitor` on real traffic. Review detections, add narrow exclusions
for known false positives, and move to `block` when the signal is useful.

| Behavior | `monitor` | `block` |
|---|---|---|
| Signature match | Log and forward | Log and reject before the backend |
| Inspectable body above `max_body_bytes` | Forward intact; log skipped inspection | Reject with `413` |
| Response to a blocked request | Not applicable | Configurable `4xx` and request ID |

Exclusions can combine route prefix, method, parameter name, and detection
category. Empty arrays match **any** value on that axis, so keep them narrow:

```json
{
  "path_prefix": "/admin/report/search",
  "methods": ["POST"],
  "parameters": ["query"],
  "categories": ["sqli"]
}
```

## Run your own backend

Go 1.24+ is required to build from source. Start an HTTP backend on a private
address, then point `upstream.url` at it:

```bash
cp config.example.json config.json
# Edit upstream.url and review the forwarded-header trust setting.
go run ./cmd/minimal-waf -config ./config.json -check-config
make build
./bin/minimal-waf -config ./config.json
```

The example configuration listens on `127.0.0.1:8081`, forwards to
`http://127.0.0.1:8080`, and starts in `monitor`. Common deployment settings
can also be supplied through `MINIMAL_WAF_LISTEN_ADDRESS`,
`MINIMAL_WAF_UPSTREAM_URL`, `MINIMAL_WAF_MODE`, and
`MINIMAL_WAF_MAX_BODY_BYTES`.

### Configuration at a glance

The full starting point is [config.example.json](config.example.json).

| Setting | Purpose |
|---|---|
| `server.listen_address` | WAF listener; keep it restricted to your edge proxy |
| `upstream.url` | Private HTTP(S) backend URL |
| `upstream.preserve_host` | Preserve the original Host for backend virtual hosts |
| `upstream.trust_forwarded_headers` | Preserve the edge proxy's forwarded chain only when that proxy is trusted |
| `waf.mode` | `monitor` or `block` |
| `waf.max_body_bytes` | Maximum buffered and inspected body size |
| `waf.max_decode_passes` | Maximum repeated-decoding passes |
| `waf.block_status` | Response status for signature blocks |
| `waf.inspect_methods` / `enabled_categories` | Body methods and rule categories to inspect |
| `waf.exclusions` | Auditable, granular exceptions |
| `logging.file_path` | Optional rotating JSONL file in addition to stdout |

Server and shutdown timeouts are configurable; transport timeouts are explicit
in the implementation. Invalid configuration fails before the listener starts.

### Forwarded headers are a trust decision

If **only** a trusted Apache or Nginx can reach the WAF, enable
`trust_forwarded_headers` to preserve its forwarding chain. Restrict the WAF
listener with loopback, a private network, or firewall rules. If clients can
connect directly, disable it: client-supplied `Forwarded` and `X-Forwarded-*`
are removed before trusted values are generated. Never silently trust an
internet-supplied `X-Forwarded-For`.

## Deploy

| Target | Starting point |
|---|---|
| Containers | [Dockerfile](Dockerfile) (`scratch`, static binary, non-root) and [local Compose lab](demo/compose.yaml) |
| Apache edge | [Public reverse-proxy virtual host](deploy/apache/public-vhost.conf) |
| Nginx edge | [Nginx reverse-proxy configuration](deploy/nginx/minimal-waf.conf) |
| systemd | [Hardened service unit](deploy/systemd/minimal-waf.service) |
| Apache/PHP backend | [Private backend example](deploy/apache/backend-vhost.conf) |

The Apache/PHP files are **examples**, not a requirement. The WAF does not
terminate TLS and should not be the internet-facing component. In a
multi-container deployment, publish only the edge proxy; keep WAF and backend
ports on private networks.

For a single Linux host, build the image with `docker build -t minimal-waf .`,
mount your config read-only, and use host networking only if your edge proxy
and backend already bind to loopback. The [demo Compose file](demo/compose.yaml)
shows the private-network pattern.

## Observe it

| Signal | Where |
|---|---|
| Detection and operational logs | JSON on stdout; optional rotating JSONL file |
| Health | `GET /_minimal-waf/healthz` |
| Counters | `GET /_minimal-waf/metrics` (Prometheus text format) |
| Request correlation | `X-Request-ID` response header |
| Shutdown | Graceful on `SIGINT` and `SIGTERM` |

Operational endpoints are handled by the WAF and **never** forwarded to your
app. Deny `/_minimal-waf/` at the public edge, as the deployment examples do.

Detection logs record rule IDs, categories, locations, parameter names, method,
path, client IP, mode, and request ID—not full bodies, complete parameter
values, cookies, or authorization headers. Avoid placing sensitive data in URL
paths or parameter **names**, which are logged.

Set `logging.file_path` to an absolute path to keep a local copy alongside
stdout. [Lumberjack](https://github.com/natefinch/lumberjack) rotates when the
active file reaches `logging.max_size_mb`; `max_backups` and `max_age_days`
limit retained backups, and `compress` controls gzip compression. New files
use mode `0600`; the supplied systemd unit and demo volume provide writable
log directories. Use **one WAF process per log file**. `max_age_days` is
retention, not a daily rotation schedule.

## Security boundaries

`minimal-waf` is defense in depth, not a guarantee that requests are harmless.

- Signature rules can miss attacks or flag legitimate administrative input.
- File uploads are not scanned; only multipart text fields and filenames are.
- It does not replace secure application code, patching, authentication,
  authorization, rate limiting, or application-specific validation.
- A private backend and a trusted edge proxy are part of the security model.
- Start in `monitor`, measure false positives, and use exclusions sparingly.

Found a vulnerability or bypass? Please use the private reporting process in
[SECURITY.md](SECURITY.md), not a public issue with exploit details.

## Build with us

Small, reviewable changes are welcome. Before opening a pull request:

```bash
gofmt -w .
go vet ./...
go test -race ./...
CGO_ENABLED=0 go build -trimpath ./cmd/minimal-waf
```

New rules should have stable IDs, RE2-compatible patterns, malicious and
benign regression cases, and encoded-payload tests. Keep commits focused and
use `type(scope): description`.

If this project earns a place in your stack, [star it](https://github.com/7acini/minimal-waf),
[share a use case](https://github.com/7acini/minimal-waf/issues), or help make
the next rule safer. The goal is a WAF that stays small enough to understand.

MIT licensed. See [LICENSE](LICENSE).
