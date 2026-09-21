# Local security lab

This is an **intentionally vulnerable** PHP application for demonstrating the
minimal-waf request path. Do not deploy it on a public server or attach it to a
shared production network.

```text
browser → 127.0.0.1:8088 → Nginx → minimal-waf → Apache/PHP
                               edge network     internal backend network
```

Only Nginx publishes a host port, and that port is bound to loopback. The WAF
and PHP containers have no published ports. Nginx replaces any incoming
forwarded-header chain with its own values. The lab uses plain HTTP on localhost;
it does not move TLS termination into Go.

## Start and stop

From the repository root:

```bash
docker compose -f demo/compose.yaml up --build -d
docker compose -f demo/compose.yaml ps
```

Open <http://127.0.0.1:8088>. The page has separate inputs for:

| Input | Deliberate bug | Safe example | Expected blocked example |
|---|---|---|---|
| Product search (`POST term`) | SQL string concatenation | `Pen` | `' OR 1=1 -- ` |
| Message (`GET message`) | Unescaped HTML output | `Hello` | `<script>alert(1)</script>` |
| File path (`GET file`) | Unvalidated local file read | `welcome.txt` | `../../../../etc/passwd` |

The SQLite database is in memory and rebuilt per request. It contains only
three toy products. The file-read vulnerability stays inside the PHP container;
no host directories or credentials are mounted into that container.

Run the smoke checks:

```bash
bash demo/smoke.sh
```

For manual verification, a blocked request should return `403` and a
`X-Request-ID` header, without application HTML:

```bash
curl -i -G --data-urlencode 'file=../../../../etc/passwd' http://127.0.0.1:8088/
curl -i -G --data-urlencode 'message=<script>alert(1)</script>' http://127.0.0.1:8088/
curl -i -X POST --data-urlencode "term=' OR 1=1 -- " http://127.0.0.1:8088/
```

Watch WAF detection logs without reading the vulnerable PHP response:

```bash
docker compose -f demo/compose.yaml logs -f waf
```

The same JSON events are written to `/var/log/minimal-waf/waf.jsonl` in the WAF
container. The `waf-logs` Docker volume survives `docker compose down` and
stores rotated backups. To copy the current file out for inspection:

```bash
docker compose -f demo/compose.yaml cp waf:/var/log/minimal-waf/waf.jsonl /tmp/minimal-waf-lab.jsonl
```

The file contains security metadata; restrict access to copies and backups.
`docker compose down -v` removes the volume and its logs, so use that only when
you explicitly intend to delete them.

To observe rather than block, change `waf.mode` in `demo/waf.json` to
`monitor` and recreate only the WAF container. In that mode the attack reaches
the intentionally vulnerable application, so **do not open untrusted links or
expose the listener**. Restore `block` before normal use.

```bash
docker compose -f demo/compose.yaml down
```

The lab is not a security benchmark. Signature detection is incomplete by
design; successful blocking of these examples does not make the PHP code safe.
