# Validierung · 9. Oktober 2026

## Ausgeführt

- `go vet ./...` – erfolgreich.
- `go test -race -count=1 ./...` – erfolgreich; neun Testgruppen und elf Untertests.
- `node --check web/static/app.js` – erfolgreich.
- `docker compose config --quiet` – erfolgreich.
- Docker-Multistage-Build – erfolgreich; finales `scratch`-Image ca. 24 MB.
- Laufzeit im finalen Image: UID/GID 10001, read-only Root-Dateisystem, alle Linux-Capabilities entfernt.
- Frisches Named Volume: Login, Konfigurationsspeicherung und authentifizierte Prometheus-Metriken erfolgreich.
- Neustart mit demselben Volume: Konfigurationsrevision und Einstellung erhalten; neue Anmeldung erfolgreich.
- Live-Proxy-Test: zwölf legitime Requests mit 200 weitergeleitet, drei Angriffe mit 403 blockiert; Ereignisse korrekt als erlaubt/blockiert klassifiziert.
- Browser: Anmeldung, Proxy-Host anlegen, eigene Regel erstellen, Schutzeinstellungen speichern, Ereignisfilter und Dashboard mit realen Requests geprüft. Keine Console-Warnungen/-Fehler in der finalen Ansicht.

![Dashboard nach dem Live-Test](dashboard.jpg)

## Abgedeckte Regressionen

SQL Injection, XSS, Path Traversal, JSON-/Form-Bodies, unveränderte Body-Weiterleitung, Detection Only, unbekannte Hosts, gefälschte Forwarding-Header, Log-Redaktion, eigene Regeln, Content-Length-/Chunked-Body-Limits, CIDR-Sperr-/Zugriffslisten, Rate Limit, Pfadgrenzen, Round Robin, deaktivierte Routen, Konfigurationsvalidierung/-persistenz, Revisionskonflikte, Passwort-Login, CSRF, Origin-Prüfung, Logout, Antwortgrößenlimit, CRS-Antwortblockierung, ungültige Backend-TLS-Zertifikate, WebSocket-Handshake/Tunnel, fehlerhaftes JSON, komprimierte Request-Bodies, Absolute-Form-Requests und parallele Requests während eines Konfigurationswechsels.

## Testumgebung und offene Validierung

Getestet auf Linux/amd64 in Docker Desktop. Der offizielle Go-Image-Download wurde in der lokalen Netzwerkumgebung mit HTTP 403 abgewiesen. Stattdessen wurde Go 1.26.8 aus dem offiziellen Alpine-Paketrepository in einem separaten Buildcontainer installiert; das bereits auf dem Windows-Host vertrauenswürdige öffentliche Firmen-Proxy-CA-Zertifikat wurde für die TLS-Prüfung übernommen. Die CRS-Pakete wurden wegen eines Modulproxy-Downloadfehlers direkt aus den offiziellen Git-Repositories aufgelöst. `go.sum` ist vorhanden.

Das Dockerfile wurde mit `--build-arg BUILDER_IMAGE=bastionwaf-build-tools:local` getestet; der Standard-Builder bleibt `golang:1.26-alpine`. Das lokale Testimage enthält deshalb auch die öffentliche Firmen-Proxy-CA im CA-Bundle. Für Deployment außerhalb dieser Umgebung regulär mit dem Standard-Builder neu bauen.

Nicht ausgeführt: Deployment in den tatsächlichen LXC, externe DNS-/Router-Konfiguration, öffentliche ACME-Zertifikatsausstellung, Lasttest mit Zielanwendungen, externer Penetrationstest. Der Source-Build und das Non-Root-Laufzeitimage wurden lokal validiert; das ersetzt diese Zielumgebungsprüfungen nicht.

Die lokale Vorschau auf `127.0.0.1:19090` ist eine separate Testinstanz. Demo-Route, Demo-Backend, Preview-Passwort und deren Daten liegen unter dem Git-ignorierten `.tools/` und sind nicht Teil des produktiven Compose-Deployments. Das Demo-Backend wurde nur für diesen Testprozess gestartet; nach einem manuellen Container-Neustart muss es mit `docker exec -d bastion-preview /preview/demo` erneut gestartet werden oder die Demo-Route entfernt werden.
