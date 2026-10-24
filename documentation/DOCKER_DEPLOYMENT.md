# Docker deployment guide

How to build, deploy, and manage RDPHoney with Docker and Docker Compose.

## Prerequisites

- [Docker Engine](https://docs.docker.com/engine/install/) (v20.10+) or [Docker Desktop](https://docs.docker.com/desktop/)
- [Docker Compose](https://docs.docker.com/compose/) (v2.0+)

## Architecture in Docker

The Compose deployment has two services:

1. `rdphoney`: the .NET 10 honeypot application, listening on port `3389` (or a custom host port), hardened with `no-new-privileges:true`, `cap_drop: [ALL]`, a `512m` memory cap, and a `MAX_CONCURRENT_CONNECTIONS` semaphore limit.
2. `db-admin`: a lightweight, **read-only** SQLite web UI (`sqlite-web -r`) that mounts the same database file and binds **strictly to `127.0.0.1:8080`** on the host so it is never exposed to the public internet.
3. Host data volume (`./data`): the database file (`RdpHoneypotLogs.db`) lives directly on the host filesystem in the `./data` folder through a bind mount.

```
+-------------------------------------------------------------+
| HOST MACHINE                                                |
|                                                             |
|   +-------------------+              +------------------+   |
|   | DB Browser for    |              | Host Web Browser |   |
|   | SQLite / DBeaver  |              |                  |   |
|   +---------+---------+              +--------+---------+   |
|             | (direct file access)            |             |
|             v                                 | (HTTP)      |
|      ./data/RdpHoneypotLogs.db                v             |
|             ^                         http://localhost:8080 |
|             |                                 |             |
+-------------|---------------------------------|-------------+
              | (bind mount)                    |
+-------------v---------------------------------v-------------+
| DOCKER CONTAINERS                                           |
|                                                             |
|   +---------------------+             +-----------------+   |
|   | rdphoney container  |             | db-admin        |   |
|   |                     |             | (sqlite-web)    |   |
|   | Port: 3389 (RDP)    |             | Port: 8080      |   |
|   | Path: /app/data/... |             | Path: /data/... |   |
|   +---------------------+             +-----------------+   |
+-------------------------------------------------------------+
```

## Deployment with Docker Compose

### Step 1: Clone the repository

```bash
git clone https://github.com/dmitryporotnikov/RDPHoneyPot.git
cd RDPHoneyPot
```

### Step 2: (Optional) Configure environment variables

Copy the example environment file:

```bash
cp .env.example .env
```

Edit `.env` if you want custom ports, want to enable AbuseIPDB auto-reporting, or want to disable auto-banning during initial testing:

```ini
HONEYPOT_PORT=3389
DB_ADMIN_PORT=8080
DATABASE_PATH=/app/data/RdpHoneypotLogs.db
MAX_CONCURRENT_CONNECTIONS=64
# Disable auto-ban while testing from your management machine
AUTO_BAN_RDP_CLIENTS=false

# Optional: Automatically report banned RDP clients to AbuseIPDB
ABUSEIPDB_API_KEY=
ABUSEIPDB_ENABLED=true
ABUSEIPDB_CATEGORIES=18,15
ABUSEIPDB_EXCLUDED_IPS=
```

### Step 3: Build and start the containers

```bash
docker compose up -d --build
```

### Step 4: Verify the services

```bash
docker compose ps
```

Expected output:

```text
NAME                 IMAGE                         STATUS         PORTS
rdphoney             rdphoneypot-rdphoney          Up             0.0.0.0:3389->3389/tcp
rdphoney-db-admin    ghcr.io/coleifer/sqlite-web   Up             127.0.0.1:8080->8080/tcp
```

### Step 5: Check the honeypot logs

```bash
docker compose logs -f rdphoney
```

## Working with the database from the host

`./data` is bind-mounted between the host and the containers, so you have several ways in:

### Method 1: Host web browser (no installation)

Open:

```text
http://localhost:8080
```

The SQLite web admin panel lets you browse `ConnectionLogs`, run SQL queries, filter by IP address, and export to CSV.

### Method 2: Desktop SQLite GUI tools

Open the database file directly on the host:

```text
./data/RdpHoneypotLogs.db
```

Compatible tools:

- DB Browser for SQLite (https://sqlitebrowser.org/)
- DBeaver (https://dbeaver.io/)
- DataGrip (JetBrains)
- VS Code SQLite Viewer extension

RDPHoney uses SQLite WAL (Write-Ahead Logging) mode, so you can open, query, and inspect the database from host tools while the honeypot keeps running, without locking it.

## Standalone Docker run (without Compose)

If you prefer plain `docker run`:

### 1. Build the image

```bash
docker build -t rdphoney:latest .
```

### 2. Create the host data directory

```bash
# On Linux / macOS:
mkdir -p data

# On Windows PowerShell:
New-Item -ItemType Directory -Path "data" -Force
```

### 3. Run the container

```bash
# On Linux / macOS:
docker run -d \
  --name rdphoney \
  --restart unless-stopped \
  -p 3389:3389 \
  -v "$(pwd)/data:/app/data" \
  rdphoney:latest

# On Windows PowerShell:
docker run -d `
  --name rdphoney `
  --restart unless-stopped `
  -p 3389:3389 `
  -v "${PWD}/data:/app/data" `
  rdphoney:latest
```

## Deploying on a Public Linux VPS (Step-by-Step Guide)

Follow this checklist when deploying RDPHoney on a cloud VPS (DigitalOcean, Hetzner, Linode, AWS EC2, Azure, Vultr, etc.):

### 1. Configure VPS Firewall (`ufw` / Cloud Security Group)

Only TCP port `3389` (and your SSH port) should be open to the internet. Because `db-admin` binds to `127.0.0.1:8080`, it is already unreachable from external interfaces, and keeping port `8080` closed at the firewall adds defense in depth:

```bash
sudo ufw allow OpenSSH
sudo ufw allow 3389/tcp
sudo ufw enable
sudo ufw status
```

### 2. Clone the Repository and Configure `.env`

```bash
git clone https://github.com/dmitryporotnikov/RDPHoneyPot.git
cd RDPHoneyPot
cp .env.example .env
nano .env
```

Recommended production `.env` on a VPS:

```ini
HONEYPOT_PORT=3389
DB_ADMIN_PORT=8080
DATABASE_PATH=/app/data/RdpHoneypotLogs.db
STATIC_JPG_PATH=/app/assets/desktop.jpg
AUTO_BAN_RDP_CLIENTS=true
MAX_CONCURRENT_CONNECTIONS=64

# Optional: Enable automatic AbuseIPDB reporting
ABUSEIPDB_API_KEY=your_abuseipdb_v2_api_key_here
ABUSEIPDB_ENABLED=true
ABUSEIPDB_CATEGORIES=18,15
# Add your own home/office static IP here so your own test connections are never reported
ABUSEIPDB_EXCLUDED_IPS=203.0.113.50
```

> **How Home/VPS IP Protection Works:**
> - On startup, RDPHoney automatically queries `api.ipify.org` to resolve the VPS's own public IP and adds it to the exclusion list.
> - All loopback (`127.0.0.0/8`, `::1`), RFC 1918 private (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local (`169.254.0.0/16`), and CGNAT (`100.64.0.0/10`) ranges are never reported.
> - Any IPs listed in `ABUSEIPDB_EXCLUDED_IPS` are also excluded.
> - Each reported IP has a 15-minute cooldown in SQLite (`ReportedToAbuseIPDB = 1`) to respect AbuseIPDB rate limits.

### 3. Launch the Honeypot

```bash
docker compose up -d --build
docker compose logs -f rdphoney
```

### 4. View the SQLite Web UI Remotely via SSH Tunnel

Because `rdphoney-db-admin` is bound to `127.0.0.1:8080` in read-only mode, connect to it from your local machine using an SSH local port forward:

```bash
ssh -L 8080:127.0.0.1:8080 user@your-vps-ip
```

While the SSH session is open, visit `http://localhost:8080` in your local browser to inspect `ConnectionLogs`, captured credentials, and `ReportedToAbuseIPDB` / `AbuseConfidenceScore` columns.

## Stopping and updating

Stop the services:

```bash
docker compose down
```

Update to the latest code:

```bash
git pull
docker compose up -d --build
```

The database and attack logs stay intact in `./data/RdpHoneypotLogs.db`.