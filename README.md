# RDPHoneyPot

[![.NET 10](https://img.shields.io/badge/.NET-10.0%20LTS-512BD4?logo=dotnet)](https://dotnet.microsoft.com/)
[![Docker](https://img.shields.io/badge/Docker-compose-2496ED?logo=docker&logoColor=white)](docker-compose.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

An RDP honeypot in C#. It speaks enough of MS-RDPBCGR to hold a real conversation with a client, which means it can tell a person using `mstsc.exe` from a scanner or a brute-force tool, and it collects credentials from both.

![Screenshot](screenshot.png)

## What it does

It negotiates RDP with a dynamically generated self-signed certificate. Interactive clients get a Windows logon screen, Fast-Path keystroke capture, and a static desktop image streamed back after they type anything; every credential is accepted. Tools like Hydra, Crowbar and Ncrack send usernames and passwords in the protocol-level Client Info PDU, which the honeypot reads directly.

Captured usernames, passwords, source IPs and UTC timestamps go into SQLite at `./data/RdpHoneypotLogs.db`. Sessions are held for a random 3 to 6 seconds and then dropped. If `AUTO_BAN_RDP_CLIENTS` is on, repeat clients are refused before the TLS handshake, so known scanners don't eat handshake resources.

Everything is .NET 10 with no native dependencies, and a single `docker compose up` brings up the honeypot plus a `sqlite-web` console on port 8080. The database runs in WAL mode, so you can query it from the host while the honeypot keeps writing.

`EnrichReportWithIPDB.ps1` adds AbuseIPDB confidence scores, ISP, geolocation and Tor exit status to the captured logs.

## Run it

Docker Compose is the intended path:

```bash
git clone https://github.com/dmitryporotnikov/RDPHoneyPot.git
cd RDPHoneyPot
docker compose up -d --build
docker compose ps
```

The honeypot listens on `3389`, the database UI on `http://localhost:8080`.

With the .NET 10 SDK instead:

```bash
dotnet restore
dotnet build -c Release
dotnet run --project RDPHoney -c Release
dotnet test
```

## Configuration

Set these in the environment or in `.env` next to `docker-compose.yml`:

| Variable | Default | What it does |
|---|---|---|
| `HONEYPOT_PORT` | `3389` | TCP port for RDP traffic. |
| `DATABASE_PATH` | `data/RdpHoneypotLogs.db` | SQLite file. |
| `DB_ADMIN_PORT` | `8080` | Port for the sqlite-web UI. |
| `STATIC_JPG_PATH` | `assets/desktop.jpg` | Image shown to authenticated clients. |
| `AUTO_BAN_RDP_CLIENTS` | `true` | Drop IPs already logged as RDP clients. |

[documentation/CONFIGURATION.md](documentation/CONFIGURATION.md) has the full set, including aliases.

## Reading the capture

The database is mounted from the host, so DB Browser for SQLite, DBeaver or the CLI all work:

```bash
sqlite3 -header -column data/RdpHoneypotLogs.db \
  "SELECT Id, IPAddress, Username, Password FROM ConnectionLogs WHERE Username IS NOT NULL;"
```

## Documentation

- [Architecture](documentation/ARCHITECTURE.md): packet handling, protocol simulation, capture and classification.
- [Docker deployment](documentation/DOCKER_DEPLOYMENT.md): volumes, firewall rules, container management.
- [Database guide](documentation/DATABASE_GUIDE.md): schema, WAL concurrency, queries from the host.
- [Configuration](documentation/CONFIGURATION.md): environment variables and ports.
- [Threat intelligence](documentation/ANALYSIS_AND_ENRICHMENT.md): AbuseIPDB enrichment and SIEM export.

## License

MIT. See [LICENSE](LICENSE).
