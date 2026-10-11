# Docker deployment guide

How to build, deploy, and manage RDPHoney with Docker and Docker Compose.

## Prerequisites

- [Docker Engine](https://docs.docker.com/engine/install/) (v20.10+) or [Docker Desktop](https://docs.docker.com/desktop/)
- [Docker Compose](https://docs.docker.com/compose/) (v2.0+)

## Architecture in Docker

The Compose deployment has two services:

1. `rdphoney`: the .NET 10 honeypot application, listening on port `3389` (or a custom host port).
2. `db-admin`: a lightweight SQLite web UI (`sqlite-web`) that mounts the same database file and exposes port `8080` to the host.
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

Edit `.env` if you want custom ports or want to disable auto-banning during initial testing:

```ini
HONEYPOT_PORT=3389
DB_ADMIN_PORT=8080
DATABASE_PATH=/app/data/RdpHoneypotLogs.db
# Disable auto-ban while testing from your management machine
AUTO_BAN_RDP_CLIENTS=false
```

A note on real client IP preservation: in standard Docker bridge networking, Docker's userland proxy applies Source NAT (SNAT), so all incoming connections appear to come from the Docker gateway or bridge IP (for example `192.168.3.0` or `172.x.x.x`). `docker-compose.yml` uses `network_mode: host` on Linux, which lets the honeypot see the actual attacker or client IP straight from the kernel network stack, without NAT.

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
rdphoney-db-admin    ghcr.io/coleifer/sqlite-web   Up             0.0.0.0:8080->8080/tcp
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

## Exposing RDPHoney to the internet

To collect real attacker traffic, port 3389 must be reachable from the public internet:

1. Cloud virtual machines (AWS EC2, Azure VM, DigitalOcean, GCP):
   - Configure the security group or firewall rules:
     - Allow inbound TCP on port `3389` from `0.0.0.0/0`.
     - Allow inbound TCP on port `8080` only from your administrative IP. Never expose port 8080 to the public internet without authentication.
2. On-premise or home lab:
   - Set up port forwarding on your router: forward external port `3389` to the host machine's local IP on port `3389`.
   - Consider running RDPHoney in an isolated DMZ or VLAN.

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