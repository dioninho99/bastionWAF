# Bastion WAF

Ein integriertes HTTP-Gateway für einen **separaten Linux-LXC mit Docker**. Reverse Proxy, Coraza-WAF, OWASP Core Rule Set und deutsche Verwaltungsoberfläche laufen in **einem Prozess und einem Container**. Ein zusätzlicher Nginx oder Traefik ist nicht erforderlich.

```text
Internet / Clients → LXC :80 / :443 → Bastion → HTTP(S)-Anwendungen im internen Netz
Administrator → SSH-Tunnel / Management-Netz → LXC :9090 → Bastion Admin
```

## Stand

Erste funktionsfähige Ausbaustufe, kein Versprechen vollständiger Enterprise-WAF-Parität. Die Implementierung verwendet echte Coraza-Transaktionen mit OWASP CRS, keine selbstgeschriebenen Regex-Listen als Ersatz. Integrationstests prüfen Blockierung **vor** Backend-Zugriff, Body-Weiterleitung, Antwortprüfung, TLS-Verifikation, WebSockets, Zugriffskontrolle, Authentifizierung und Konfigurationswechsel. Vor dem produktiven Einsatz Regeln mit den eigenen Anwendungen abstimmen und Last-/Sicherheitstests in der Zielumgebung durchführen.

## Enthalten

- Deutsche, responsive GUI: Dashboard, Hosts, WAF-Einstellungen, eigene Regeln, Ereignisse und Konfigurationsexport/-import.
- Exaktes Host-Routing und längster passender Pfad-Präfix mit Pfadsegment-Grenzen; Route deaktivieren und löschen.
- HTTP-/HTTPS-Upstreams mit Zertifikatsprüfung, wahlweise Original-Host, Round-Robin über bis zu 16 Backends pro Route.
- WebSocket-Upgrades; der HTTP-Handshake wird geprüft, Frames nach dem Upgrade werden durchgereicht.
- TLS 1.2+, manuelle PEM-Zertifikate oder automatische Let's-Encrypt-Zertifikate für aktivierte Hosts.
- Coraza **3.8.1**, CRS-Paket **4.25.0** (Versionen im `go.mod`/`go.sum` fixiert).
- SQLi, XSS, Traversal, Command-Injection und weitere CRS-Kategorien; Query-, Header-, JSON-, Form- und Multipart-Prüfung gemäß CRS/Coraza-Konfiguration.
- Blocking/Detection Only, Paranoia Level 1–4, Anomalie-Schwellenwert und gezielte CRS-Ausnahmen pro Route.
- Eigene Regeln für Pfad, User-Agent und Methode; wörtliche, case-insensitive Teilstrings; blockieren oder protokollieren.
- IPv4-/IPv6-CIDR-Sperrliste und optionale Zugriffsliste. Sperren haben Vorrang; erlaubte Clients umgehen die WAF nicht.
- Fixed-Window-Rate-Limit pro IP und Route, Body-Limits, Timeouts, Connection-Limits und begrenzte Prüfpuffer.
- Optionale Antwortprüfung für von Coraza unterstützte MIME-Typen, vor der Übertragung an den Client.
- Ereignisse mit Request-ID, CRS-IDs, IP, Host, Pfad, Status und Dauer; JSON-Export und rotierende JSONL-Dateien.
- Passwort-Login, HttpOnly-/SameSite-Cookies, CSRF- und Origin-Prüfung, Login-Limit und geschützte Prometheus-Metriken.
- Atomare Konfigurationsspeicherung und Aktivierung ohne Neustart; Revisionen verhindern konkurrierendes Überschreiben.

## Start im LXC

Voraussetzung: Linux-LXC mit funktionierendem Docker Engine und Compose v2. Der LXC benötigt Netzwerkzugriff auf die Backends und auf öffentliche Registries/Go-Module beim Build. Für Docker im LXC muss der Virtualisierungshost die nötige Container-Unterstützung bereitstellen. Keine pauschale Deaktivierung von AppArmor oder Firewall notwendig; hostabhängige LXC-Einstellungen mit dem Betreiber klären.

Als Startpunkt: 2 vCPU, 2 GiB RAM für den LXC, zusätzliche Reserve beim Build. Compose begrenzt den Dienst auf 1 GiB RAM und 2 CPUs; tatsächliche Kapazität mit den eigenen Requests messen.

Im geklonten Projekt:

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

Das Secret ist das GUI-Passwort. Es wird nicht ins Image oder in `config.json` geschrieben. Mindestens 20 Zeichen sind erforderlich. Kein Standardpasswort vorhanden. Die Secret-Datei muss für UID 10001 im Container lesbar sein; die Befehle oben setzen dazu Eigentümer und Leserechte.

Das Datenvolume wird beim ersten Start mit Eigentümer UID 10001 aus dem Image initialisiert. Die Konfiguration bleibt über Container-Neustarts erhalten.

### Admin-Zugang

Standardmäßig bindet der veröffentlichte Admin-Port ausschließlich an **127.0.0.1 im LXC**. Vom eigenen Rechner:

```sh
ssh -L 9090:127.0.0.1:9090 dein-user@LXC-IP
```

Dann [http://localhost:9090](http://localhost:9090) öffnen und mit dem Secret anmelden. Der Tunnel verschlüsselt den Transport. Für direkten Zugriff im Management-Netz kann `BASTION_ADMIN_BIND` auf die interne LXC-IP gesetzt werden; der Admin-Listener selbst bietet in dieser Version nur HTTP. Deshalb SSH-/VPN-Zugang verwenden und Port 9090 nicht ins Internet weiterleiten. Er ist **kein** Pfad am öffentlichen Proxy-Listener.

### Erste Anwendung

1. Unter **Proxy Hosts → Proxy Host hinzufügen** einen Namen eintragen.
2. Domain, z. B. `cloud.example.com`, und Pfad `/` angeben.
3. Backend, z. B. `http://10.20.0.15:8080`, eintragen. `localhost` bezeichnet den Bastion-Container, nicht einen anderen LXC.
4. Route aktivieren und speichern.
5. DNS der Domain auf das Gateway zeigen lassen; im Router ausschließlich Ports 80/443 zum LXC weiterleiten.

Test vor der DNS-Umstellung:

```sh
curl -i -H 'Host: cloud.example.com' http://LXC-IP/
curl -i -H 'Host: cloud.example.com' 'http://LXC-IP/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E'
```

Im Blocking-Modus sollte die zweite Anfrage mit 403 enden. Die Oberfläche zeigt den Regeltreffer. Der Test muss gegen eine eigene, konfigurierte Anwendung erfolgen.

### HTTPS

**Let's Encrypt:** In `.env` eine echte `BASTION_ACME_EMAIL` setzen und `docker compose up -d` ausführen. Dadurch werden ACME und die HTTP→HTTPS-Weiterleitung aktiviert. Mit Aktivierung werden die Let's-Encrypt-Nutzungsbedingungen akzeptiert. Domain-DNS, Port 80 und Port 443 müssen von außen auf diesen LXC zeigen. Zertifikate werden bei Bedarf ausschließlich für aktivierte Hosts angefordert und unter `/data/acme` erneuert/gecached. Unbekannte Hosts erhalten keine Zertifikate. ACME-Erteilung braucht eine echte Domain und wurde nicht durch die lokalen Tests validiert.

**Eigene Zertifikate:** `fullchain.pem` und `privkey.pem` nach `certs/` legen. Verzeichnis und Dateien müssen für UID 10001 zugänglich sein, z. B. mit `sudo chown 10001:10001 certs certs/fullchain.pem certs/privkey.pem`, Verzeichnismodus 700 und Dateimodus 400. In `.env`:

```dotenv
BASTION_ACME_EMAIL=
BASTION_TLS_CERT=/certs/fullchain.pem
BASTION_TLS_KEY=/certs/privkey.pem
```

Container neu starten. Das Zertifikat muss alle verwendeten Domains abdecken. Manuelle Zertifikate benötigen nach Erneuerung einen Neustart. Ohne ACME/PEM bleibt der Proxy auf HTTP; der veröffentlichte 443-Port hat dann keinen Listener. HTTP-Redirects zielen auf den Standardport 443.

## Betriebsverhalten und Grenzen

- **Single Instance:** Konfiguration auf lokalem Volume; Rate Limits, Sitzungen und Dashboard-Zähler im Arbeitsspeicher. Keine verteilten Limits oder HA-Synchronisierung. Sitzungen enden nach acht Stunden oder Neustart. Das JSONL-Archiv bleibt erhalten; die GUI zeigt nur bis zu 1.000 Ereignisse des aktuellen Prozesses.
- **Direkter Edge-Betrieb:** Client-IP kommt vom TCP-Peer. Übermittelte `Forwarded`, `X-Forwarded-*` und `X-Real-IP` werden verworfen/neu aufgebaut. Keine Trusted-Proxy-/CDN-Unterstützung. Eine NAT-/Docker-Konfiguration, die die Client-IP maskiert, führt zu gemeinsamen IP-Limits; im LXC verifizieren.
- **Uploads:** Standard 2 MiB pro Request, konfigurierbar 1 KiB–32 MiB. Vor Weiterleitung wird der komplette Request gepuffert. Komprimierte Request-Bodies werden mit 415 abgewiesen. Unvollständige Prüfung führt nicht zu ungeprüfter Weiterleitung.
- **Antwortprüfung:** Standardmäßig aus, um Streaming/Downloads nicht unnötig zu puffern. Bei Aktivierung maximal 1 MiB für prüfbare MIME-Typen; größere oder komprimierte prüfbare Antworten werden mit 502 verworfen. Binärinhalte sind kein Malware-Scan. SSE-/Langzeit-Streaming wird durch den 60-Sekunden-Request-Timeout begrenzt. WebSocket-Frames und gRPC-Nachrichten werden nicht geprüft.
- **Limits:** Maximal 128 parallele Proxy-Anfragen/Upgrades; konservatives 256-MiB-Reservierungsbudget für Payload-Puffer. Bei ausgeschöpfter Kapazität 503. Dies ist keine volumetrische DDoS-Abwehr und garantiert keine feste Gesamtspeichergrenze für die Engine.
- **Backends:** Keine aktiven Healthchecks, automatischen Retries, Session-Affinität oder URL-Rewrites. „Aktiv“ in der GUI bedeutet konfiguriert, nicht gesund. Private HTTP(S)-Backends sind absichtlich erlaubt; nur vertrauenswürdige Administratoren dürfen Routen konfigurieren. Kein Forward Proxy.
- **Accounts:** Ein Administrator, keine Rollen, SSO oder MFA. Die Admin-API und Backend-Zugriffe sind hoch privilegiert. Ein separates, nur lesendes Monitoring-Token ist noch nicht implementiert.
- **Logs:** Keine Query-Strings, Bodies, Auth-Header oder Coraza-Match-Daten; Pfade können dennoch anwendungsspezifisch sensible Werte enthalten. Audit-Datei maximal 10 MiB plus eine Rotation. Config-Änderungen werden mit Revision und Client-IP auf stdout protokolliert; kein manipulationssicheres Audit-Archiv.
- **Noch nicht enthalten:** GeoIP/ASN-Regeln, Bot-Challenges/CAPTCHA, API-Schema-Validierung, automatisches Tuning, Threat-Intel-Feeds, Cache, HTTP/3, DNS-01-Zertifikate und Zertifikatsverwaltung in der GUI.

## Monitoring und Sicherung

Healthcheck: `GET /healthz` am Admin-Port, ohne Login. Prüft Prozess/Listener, keine Backend-Gesundheit.

Prometheus: `GET /metrics`, Admin-Sitzung oder `Authorization: Bearer <Admin-Passwort>` erforderlich. Nur aus dem vertrauenswürdigen Management-Netz abfragen; das Passwort gewährt volle Admin-Rechte. Zähler haben keine hoch-kardinalen Host-/IP-Labels.

```sh
docker compose logs -f --tail=100 bastion
```

Konfiguration im GUI exportieren; für vollständige Wiederherstellung zusätzlich das Volume `bastion_data` (Config, Logs, ACME-Keys), `secrets/`, `.env` und `certs/` geschützt sichern. Das Volume ist vor einem Image-Update zu sichern. **`docker compose down -v` löscht das Datenvolume.**

## Entwicklung und Tests

Go 1.26 empfohlen, keine Node-/Frontend-Build-Abhängigkeiten. HTML/CSS/JS werden über `go:embed` in das Binary eingebettet.

```sh
go mod download
go test -race -count=1 ./...
go vet ./...
go build ./cmd/bastion
```

Lokaler Start mit `BASTION_ADMIN_PASSWORD` (nur Entwicklung) oder `BASTION_ADMIN_PASSWORD_FILE`. Default: Proxy `:8080`, Admin `127.0.0.1:9090`, Daten `./data`.

Wichtige Umgebungsvariablen: `BASTION_DATA_DIR`, `BASTION_HTTP_ADDR`, `BASTION_HTTPS_ADDR`, `BASTION_ADMIN_ADDR`, `BASTION_ADMIN_PASSWORD_FILE`, `BASTION_ACME_EMAIL`, `BASTION_TLS_CERT`, `BASTION_TLS_KEY`. Der eingebaute Docker-Healthcheck erwartet den Admin-Port 9090.

```text
cmd/bastion/         Einstieg, Listener, TLS/ACME, Shutdown
internal/gateway/   Config, Coraza, Proxy, Admin-API, Ereignisse, Tests
web/static/         GUI ohne externe CDN-Abhängigkeiten
compose.yaml        LXC-/Docker-Deployment
```

Referenzen: [Coraza](https://coraza.io/docs/), [OWASP CRS](https://coreruleset.org/docs/), [Go ReverseProxy](https://pkg.go.dev/net/http/httputil#ReverseProxy), [autocert](https://pkg.go.dev/golang.org/x/crypto/acme/autocert).
