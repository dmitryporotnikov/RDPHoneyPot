# RDPHoneyPot

A lightweight RDP honeypot for attracting and analyzing Remote Desktop Protocol (RDP) attacks and scans, written in C# and running on .NET 10 (LTS).

## Features

- Full MS-RDPBCGR negotiation with a dynamically generated self-signed X.509 certificate, so real RDP clients can be told apart from automated port scanners.
- Interactive clients (`mstsc.exe`, FreeRDP) get a graphical Windows logon screen, real-time Fast-Path keystroke capture, and any credentials they submit are accepted.
- Brute-force tools (Hydra, Crowbar, Ncrack) send usernames and passwords in the protocol-level Client Info PDU (`TS_INFO_PACKET`), which the honeypot extracts directly.
- Captured usernames, passwords, IP addresses, and UTC timestamps are recorded to the SQLite database.
- After authentication, the client's screen shows a static desktop image (or a custom JPG) streamed via Fast-Path bitmap updates.
- The authenticated session is held for 3 to 6 seconds at random, then disconnected.
- Connections from IP addresses previously logged as RDP exploiters are dropped before they can consume TLS handshake resources.
- Runs on .NET 10 (LTS) cross-platform, with no native dependencies.
- Deploys with a single `docker compose up` command, with health monitoring and graceful shutdown.
- The database is stored at `./data/RdpHoneypotLogs.db` through a host volume mount and runs in WAL (Write-Ahead Logging) mode, so it can be inspected from the host while the honeypot keeps writing.
- A web database management UI (`sqlite-web`) is reachable from the host at `http://localhost:8080`.
- A PowerShell script (`EnrichReportWithIPDB.ps1`) enriches the collected attack logs with AbuseIPDB confidence scores, ISP details, geolocations, and Tor node identification.

![Screenshot](screenshot.png)

## Getting started

### Prerequisites

One of the following:

- Docker & Docker Compose (recommended for production or isolated deployment)
- .NET 10.0 SDK (for local development or native execution)

### Option 1: Deploy with Docker Compose (recommended)

1. Clone the repository:
   ```bash
   git clone https://github.com/dmitryporotnikov/RDPHoneyPot.git
   cd RDPHoneyPot
   ```

2. Start the honeypot and the database web UI:
   ```bash
   docker compose up -d --build
   ```

3. Check the running containers:
   ```bash
   docker compose ps
   ```

The honeypot is now listening on port `3389`, and the database is accessible at `http://localhost:8080`.

### Option 2: Run natively with the .NET 10 SDK

1. Clone the repository and restore dependencies:
   ```bash
   git clone https://github.com/dmitryporotnikov/RDPHoneyPot.git
   cd RDPHoneyPot
   dotnet restore
   ```

2. Build the project:
   ```bash
   dotnet build -c Release
   ```

3. Run the honeypot:
   ```bash
   dotnet run --project RDPHoney -c Release
   ```

4. Run the tests:
   ```bash
   dotnet test
   ```

## Credential capture and static JPG display

1. When a user or tool connects:
   - Credentials sent in the initial connection packet (typically brute-force tools) are captured immediately.
   - An interactive user (for example, via Windows Remote Desktop, `mstsc.exe`) is shown a graphical Windows login prompt.
2. Acceptance and logging:
   - The honeypot accepts any username and password entered.
   - Credentials are saved to `./data/RdpHoneypotLogs.db` in the `ConnectionLogs` table (`Username`, `Password`, `IPAddress`, `Timestamp`).
3. Static JPG display:
   - The honeypot renders `assets/desktop.jpg` to the client's screen.
   - To customize it, replace `assets/desktop.jpg` or set `STATIC_JPG_PATH` in `.env`.
4. Disconnect:
   - After a randomized delay of 3 to 6 seconds, the honeypot disconnects the session.

## Working with the database from the host

When running in Docker, the database is persisted to `./data/RdpHoneypotLogs.db` on the host. RDPHoney uses SQLite Write-Ahead Logging (WAL), so an administrator can query the database while the honeypot is actively capturing traffic:

1. Web admin UI: open `http://localhost:8080` in a browser on the host to query tables, filter captured credentials, and export CSV or JSON.
2. Desktop GUI tools: open `./data/RdpHoneypotLogs.db` in DB Browser for SQLite (shown in the screenshot above), DBeaver, or DataGrip.
3. Command line: inspect the logs with `sqlite3`:
   ```bash
   sqlite3 -header -column data/RdpHoneypotLogs.db "SELECT Id, IPAddress, Username, Password FROM ConnectionLogs WHERE Username IS NOT NULL;"
   ```

## Configuration

RDPHoney is configured through environment variables (or a `.env` file with Docker Compose):

| Environment Variable | Default | Description |
|---|---|---|
| `HONEYPOT_PORT` | `3389` | TCP port the honeypot listens on for RDP traffic. |
| `DATABASE_PATH` | `data/RdpHoneypotLogs.db` | File path to the SQLite database. |
| `DB_ADMIN_PORT` | `8080` | Port for the SQLite web admin UI in Docker Compose. |
| `STATIC_JPG_PATH` | `assets/desktop.jpg` | Path to the static JPG rendered to authenticated users. |
| `AUTO_BAN_RDP_CLIENTS` | `true` | Drop connections from IP addresses already logged as RDP clients. |

The [configuration guide](documentation/CONFIGURATION.md) lists the full set, including alias variables.

## Documentation

Detailed documentation lives in the [`documentation/`](documentation/) directory:

- [System architecture](documentation/ARCHITECTURE.md): packet handling, protocol simulation, credential capture, and connection classification.
- [Docker deployment guide](documentation/DOCKER_DEPLOYMENT.md): setup, host volume mounts, cloud firewall rules, and container management.
- [Database guide](documentation/DATABASE_GUIDE.md): schema, WAL mode concurrency, credential queries, and host access tools.
- [Configuration guide](documentation/CONFIGURATION.md): environment variables, custom ports, and static JPG customization.
- [Threat intelligence and enrichment](documentation/ANALYSIS_AND_ENRICHMENT.md): using `EnrichReportWithIPDB.ps1` with AbuseIPDB and exporting to a SIEM.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.