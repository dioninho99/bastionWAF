# Bastion WAF

An integrated HTTP gateway for a **separate Linux LXC running Docker**. The reverse proxy, Coraza WAF, OWASP Core Rule Set, and English administration UI run in **one process and one container**. No additional Nginx or Traefik instance is required.

```text
Internet / clients → LXC :80 / :443 → Bastion → HTTP(S) applications on the internal network
Administrator → SSH tunnel / management network → LXC :9090 → Bastion Admin
```

## Status

This is the first functional release, not a promise of complete enterprise-WAF parity. It uses real Coraza transactions with OWASP CRS rather than handwritten regex lists. Integration tests cover blocking before backend access, body forwarding, response inspection, TLS verification, WebSockets, access control, authentication, and configuration changes. Tune the rules for your applications and perform load and security testing in the target environment before production use.

## Included

- Responsive English GUI: dashboard, proxy hosts, WAF protection, custom rules, events, and configuration export/import.
- Exact host routing and longest matching path prefix with path-segment boundaries; routes can be disabled or deleted.
- HTTP/HTTPS upstreams with certificate verification, optional original Host header, and round-robin balancing across up to 16 backends per route.
- WebSocket upgrades; the HTTP handshake is inspected and frames are passed through after the upgrade.
- TLS 1.2+, manual PEM certificates, or automatic Let's Encrypt certificates for enabled hosts.
- Coraza **3.8.1** and CRS package **4.25.0**, pinned in `go.mod`/`go.sum`.
- SQLi, XSS, traversal, command injection, and other CRS categories, including query, header, JSON, form, and multipart inspection.
- Blocking/Detection Only, paranoia levels 1–4, anomaly threshold, and targeted CRS exclusions per route.
- Custom path, User-Agent, and method rules using literal case-insensitive substrings; rules can block or log.
- IPv4/IPv6 CIDR deny list and optional allow list. Deny rules take precedence; allowed clients still pass through the WAF.
- Fixed-window per-IP/per-route rate limiting, body limits, timeouts, connection limits, and bounded inspection buffers.
- Optional response inspection for MIME types supported by Coraza before data is sent to the client.
- Events with request ID, CRS IDs, IP, host, path, status, and duration; JSON export and rotating JSONL files.
- Password login, HttpOnly/SameSite cookies, CSRF and Origin checks, login limiting, and protected Prometheus metrics.
- Atomic configuration persistence and activation without restart; revisions prevent concurrent overwrites.

## Start in the LXC

Prerequisite: a Linux LXC with a working Docker Engine and Compose v2. The LXC needs network access to backends and public registries/Go modules during the build. Docker inside the LXC requires the virtualization host to provide the required container support. Review host-specific LXC settings with the operator; blanket AppArmor or firewall disabling is not required.

As a starting point, use 2 vCPUs and 2 GiB RAM for the LXC, with extra build capacity. Compose limits the service to 1 GiB RAM and 2 CPUs; measure actual capacity with your own traffic.

In the cloned project:

```sh
mkdir -p secrets certs
chmod 700 secrets certs
umask 077
openssl rand -hex 32 > secrets/admin_password.txt
sudo chown 10001:10001 secrets/admin_password.txt
sudo chmod 400 secrets/admin_password.txt
cp .env.example .env
docker compose up -d --build
docker compose ps
```

The secret is the GUI password. It is not written into the image or `config.json`. At least 20 characters are required; no default password exists. The secret file must be readable by UID 10001 inside the container.

The data volume is initialized with UID 10001 on first start and persists across container restarts.

### Admin access

By default, the published admin port binds only to **127.0.0.1 inside the LXC**. From your workstation:

```sh
ssh -L 9090:127.0.0.1:9090 your-user@LXC-IP
```

Open [http://localhost:9090](http://localhost:9090) and sign in with the secret. The tunnel encrypts transport. For direct management-network access, set `BASTION_ADMIN_BIND` to the internal LXC address. The admin listener is HTTP-only in this release, so use SSH/VPN access and never expose port 9090 to the Internet. It is **not** a path on the public proxy listener.

To serve the admin UI through a TLS reverse proxy such as Zoraxy, publish the admin port on the LXC management interface, set `BASTION_ADMIN_ORIGIN=https://web.cyberpotato.ch`, `BASTION_ADMIN_SECURE_COOKIE=true`, and proxy that hostname to `http://LXC-IP:9090`. Keep the admin hostname restricted to the management network. The container image defaults the admin listener to loopback; set `BASTION_ADMIN_ADDR=0.0.0.0:9090` only when a container or reverse proxy must reach it.

### First application

1. Open **Proxy Hosts → Add proxy host** and enter a name.
2. Enter a domain such as `cloud.example.com` and path `/`.
3. Enter a backend such as `http://10.20.0.15:8080`. `localhost` means the Bastion container, not another LXC.
4. Enable and save the route.
5. Point the domain DNS at the gateway and forward only ports 80/443 to the LXC.

Before changing DNS:

```sh
curl -i -H 'Host: cloud.example.com' http://LXC-IP/
curl -i -H 'Host: cloud.example.com' 'http://LXC-IP/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E'
```

In blocking mode, the second request should return 403 and the UI should show the rule match. Test only against an application you control.

## HTTPS

**Let's Encrypt:** Set a real `BASTION_ACME_EMAIL` in `.env` and run `docker compose up -d`. ACME and HTTP-to-HTTPS redirects are then enabled. Domain DNS and ports 80/443 must point to this LXC from the Internet. Certificates are requested only for enabled hosts and cached/renewed under `/data/acme`. Unknown hosts receive no certificates.

**Custom certificates:** Put `fullchain.pem` and `privkey.pem` in `certs/`, make them readable by UID 10001, and set:

```dotenv
BASTION_ACME_EMAIL=
BASTION_TLS_CERT=/certs/fullchain.pem
BASTION_TLS_KEY=/certs/privkey.pem
```

Restart the container. The certificate must cover every domain in use. Manual certificates require a restart after renewal. Without ACME or PEM files, the proxy remains HTTP-only and the published 443 port has no listener.

## Operating behavior and limits

- **Single instance:** configuration is stored on a local volume; rate limits, sessions, and dashboard counters are in memory. There are no distributed limits or HA synchronization. Sessions expire after eight hours or restart. The JSONL archive persists; the UI shows at most 1,000 events from the current process.
- **Direct edge operation:** client IP comes from the TCP peer. Forwarded, `X-Forwarded-*`, and `X-Real-IP` headers are discarded and rebuilt. There is no trusted-proxy/CDN support.
- **Uploads:** default 2 MiB per request, configurable from 1 KiB to 32 MiB. The complete request is buffered before forwarding. Compressed request bodies are rejected with 415.
- **Response inspection:** disabled by default. When enabled, inspectable MIME types are limited to 1 MiB; larger or compressed inspectable responses are rejected with 502. This is not malware scanning. WebSocket frames and gRPC messages are not inspected.
- **Capacity:** at most 128 concurrent proxy requests/upgrades and a conservative 256 MiB payload-buffer reservation budget. Exhaustion returns 503. This is not volumetric DDoS protection.
- **Backends:** no active health checks, automatic retries, session affinity, or URL rewrites. “Active” in the UI means configured, not healthy. Private HTTP(S) backends are intentionally allowed; only trusted administrators should configure routes. Bastion is not a forward proxy.
- **Accounts:** one administrator; no roles, SSO, or MFA. Admin APIs and backend access are highly privileged.
- **Logs:** query strings, bodies, authorization headers, and Coraza match data are not retained. Paths may still contain application-sensitive values. The audit file is limited to 10 MiB plus one rotation.
- **Not included:** GeoIP/ASN rules, bot challenges/CAPTCHA, API-schema validation, automatic tuning, threat-intelligence feeds, caching, HTTP/3, DNS-01 certificates, and GUI certificate management.

## Monitoring and backup

Health check: `GET /healthz` on the admin port, without login. It checks the process/listeners, not backend health.

Prometheus: `GET /metrics` with an admin session or `Authorization: Bearer <admin-password>`. Query it only from the trusted management network; the password grants full admin access.

```sh
docker compose logs -f --tail=100 bastion
```

Export configuration from the GUI. For a complete restore, also protect the `bastion_data` volume, `secrets/`, `.env`, and `certs/`. Back up the volume before image updates. **`docker compose down -v` deletes the data volume.**

## Development and tests

Go 1.26 is recommended; there are no Node/frontend build dependencies. HTML/CSS/JS are embedded into the binary with `go:embed`.

```sh
go mod download
go test -race -count=1 ./...
go vet ./...
go build ./cmd/bastion
```

For local development, use `BASTION_ADMIN_PASSWORD` or `BASTION_ADMIN_PASSWORD_FILE`. Defaults: proxy `:8080`, admin `127.0.0.1:9090`, data `./data`.

Important environment variables: `BASTION_DATA_DIR`, `BASTION_HTTP_ADDR`, `BASTION_HTTPS_ADDR`, `BASTION_ADMIN_ADDR`, `BASTION_ADMIN_ORIGIN`, `BASTION_ADMIN_SECURE_COOKIE`, `BASTION_ALLOW_PRIVATE_UPSTREAMS`, `BASTION_ADMIN_PASSWORD_FILE`, `BASTION_ACME_EMAIL`, `BASTION_TLS_CERT`, and `BASTION_TLS_KEY`. The built-in Docker health check expects admin port 9090.

For SSRF protection, private, loopback, link-local, and unspecified upstream destinations are rejected by default, including during connection establishment. If the WAF intentionally proxies trusted internal services, set `BASTION_ALLOW_PRIVATE_UPSTREAMS=true` and restrict the host/container network accordingly. The dashboard also supports a persistent light/dark theme toggle and follows the system preference on first use.

```text
cmd/bastion/        entrypoint, listeners, TLS/ACME, shutdown
internal/gateway/   config, Coraza, proxy, admin API, events, tests
web/static/         GUI without external CDN dependencies
compose.yaml        LXC/Docker deployment
```

References: [Coraza](https://coraza.io/docs/), [OWASP CRS](https://coreruleset.org/docs/), [Go ReverseProxy](https://pkg.go.dev/net/http/httputil#ReverseProxy), [autocert](https://pkg.go.dev/golang.org/x/crypto/acme/autocert).
