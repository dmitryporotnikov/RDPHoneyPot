# Docker Deployment Guide

This guide describes how to build, deploy, and manage RDPHoney in a containerized environment using Docker and Docker Compose.

---

## Prerequisites

- [Docker Engine](https://docs.docker.com/engine/install/) (v20.10+) or [Docker Desktop](https://docs.docker.com/desktop/)
- [Docker Compose](https://docs.docker.com/compose/) (v2.0+)

---

## Architecture in Docker

When deployed via Docker Compose, the deployment consists of two services:

1. **`rdphoney`**: The .NET 10 LTS honeypot application listening on port `3389` (or a custom host port).
2. **`db-admin`**: A lightweight SQLite web UI (`sqlite-web`) that mounts the same database file and exposes port `8080` to the host machine.
3. **Host Data Volume (`./data`)**: The database file (`RdpHoneypotLogs.db`) is stored directly on the host machine filesystem inside the `./data` folder via bind mount.

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

---

## Quick Deployment with Docker Compose

### Step 1: Clone the Repository
```bash
git clone https://github.com/your-username/RDPHoneyPot.git
cd RDPHoneyPot
```

### Step 2: (Optional) Configure Environment Variables
Copy the example environment file:
```bash
cp .env.example .env
```
Edit `.env` if you wish to customize ports or disable auto-banning during initial testing:
```ini
HONEYPOT_PORT=3389
DB_ADMIN_PORT=8080
DATABASE_PATH=/app/data/RdpHoneypotLogs.db
# Disable auto-ban while testing from your management machine
AUTO_BAN_RDP_CLIENTS=false
```

> **Note on Real Client IP Preservation**:
> In standard Docker bridge networking, Docker's userland proxy applies Source NAT (SNAT), making all incoming connections appear to originate from the Docker gateway/bridge IP (e.g. `192.168.3.0` or `172.x.x.x`). `docker-compose.yml` uses **`network_mode: host`** on Linux, enabling the honeypot to see the actual attacker/client IP address directly from the kernel network stack without NAT.

### Step 3: Build and Start Containers
```bash
docker compose up -d --build
```

### Step 4: Verify Services
Check running containers:
```bash
docker compose ps
```

Expected output:
```text
NAME                 IMAGE                         STATUS         PORTS
rdphoney             rdphoneypot-rdphoney          Up             0.0.0.0:3389->3389/tcp
rdphoney-db-admin    ghcr.io/coleifer/sqlite-web   Up             0.0.0.0:8080->8080/tcp
```

### Step 5: Check Honeypot Logs
```bash
docker compose logs -f rdphoney
```

---

## Interacting with the Database from the Host Machine

Because `./data` is bind-mounted between the host and container:

### Method 1: Host Web Browser (Zero Installation)
Navigate to:
```text
http://localhost:8080
```
From the host machine, you will see the SQLite Web admin panel where you can browse `ConnectionLogs`, run SQL queries, filter by IP address, and export to CSV.

### Method 2: Desktop SQLite GUI Tools
Open the database file directly on the host machine:
```text
./data/RdpHoneypotLogs.db
```
Compatible tools:
- **DB Browser for SQLite** (https://sqlitebrowser.org/)
- **DBeaver** (https://dbeaver.io/)
- **DataGrip** (JetBrains)
- **VS Code SQLite Viewer Extension**

> **Note**: RDPHoney uses SQLite **WAL (Write-Ahead Logging)** mode, meaning you can open, query, and inspect the database from host tools simultaneously without locking or halting the running honeypot!

---

## Standalone Docker Run (Without Compose)

If you prefer using pure `docker run`:

### 1. Build the Docker Image
```bash
docker build -t rdphoney:latest .
```

### 2. Create the Host Data Directory
```bash
# On Linux / macOS:
mkdir -p data

# On Windows PowerShell:
New-Item -ItemType Directory -Path "data" -Force
```

### 3. Run the Container
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

---

## Exposing RDPHoney to the Internet

To collect real-world attacker metrics, port 3389 must be accessible from the public internet:

1. **Cloud Virtual Machines (AWS EC2, Azure VM, DigitalOcean, GCP)**:
   - Configure Security Group / Firewall Rules:
     - Allow Inbound `TCP` on port `3389` from `0.0.0.0/0`.
     - Allow Inbound `TCP` on port `8080` **ONLY** from your personal administrative IP (never expose port 8080 to the public internet without authentication!).
2. **On-Premise / Home Lab**:
   - Set up Port Forwarding on your router: forward external port `3389` to your host machine's local IP on port `3389`.
   - Consider running RDPHoney in an isolated DMZ or VLAN.

---

## Stopping and Updating

### Stop Services
```bash
docker compose down
```

### Update to Latest Code
```bash
git pull
docker compose up -d --build
```
Your database and attack logs remain completely intact in `./data/RdpHoneypotLogs.db`.
