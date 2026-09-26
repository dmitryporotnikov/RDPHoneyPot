# Configuration Guide

RDPHoney is designed to run with sensible defaults out of the box while offering flexible configuration via environment variables for native and containerized deployments.

---

## Environment Variables

| Variable | Default Value | Description |
|---|---|---|
| `HONEYPOT_PORT` | `3389` | TCP port on which the honeypot listens for incoming connections. |
| `RDP_PORT` | *(alias for HONEYPOT_PORT)* | Alternative alias for `HONEYPOT_PORT`. |
| `DATABASE_PATH` | `data/RdpHoneypotLogs.db` | File path to the SQLite database. |
| `DB_PATH` | *(alias for DATABASE_PATH)* | Alternative alias for `DATABASE_PATH`. |
| `DB_ADMIN_PORT` | `8080` | Port used by Docker Compose for the `db-admin` web UI. |
| `STATIC_JPG_PATH` | `assets/desktop.jpg` | Path to the static JPG rendered to authenticated users. |
| `STATIC_IMAGE_PATH` | *(alias for STATIC_JPG_PATH)* | Alternative alias for `STATIC_JPG_PATH`. |

---

## Customizing the Static JPG

When an attacker or visitor authenticates (either via automated brute-force tools or by typing credentials into the login prompt), RDPHoney renders a static JPG to their display before disconnecting them after 3 to 6 seconds.

### Using the Default Desktop
If no static JPG is provided, RDPHoney automatically generates an authentic Windows Server desktop image (`assets/desktop.jpg`) complete with Start menu, taskbar, desktop icons, and system tray.

### Using Your Own Image
Simply replace `assets/desktop.jpg` with any `.jpg`, `.jpeg`, `.png`, or `.bmp` file, or set `STATIC_JPG_PATH`:

```bash
# In .env:
STATIC_JPG_PATH=assets/my_custom_screen.jpg
```
The honeypot automatically reads and scales the image to match the client's screen resolution.

---

## Setting Variables

### 1. In Docker Compose (`.env` file)
Create or edit `.env` in the repository root:
```ini
HONEYPOT_PORT=3389
DB_ADMIN_PORT=8080
DATABASE_PATH=/app/data/RdpHoneypotLogs.db
STATIC_JPG_PATH=assets/desktop.jpg
```

### 2. In Pure Docker (`docker run`)
```bash
docker run -d \
  -e HONEYPOT_PORT=3389 \
  -e DATABASE_PATH=/app/data/RdpHoneypotLogs.db \
  -p 3389:3389 \
  -v "${PWD}/data:/app/data" \
  -v "${PWD}/assets:/app/assets" \
  rdphoney:latest
```

### 3. On Windows (PowerShell)
```powershell
$env:HONEYPOT_PORT = "3389"
$env:STATIC_JPG_PATH = "C:\Honeypot\assets\desktop.jpg"
dotnet run --project RDPHoney
```
