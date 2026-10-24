# Configuration guide

RDPHoney runs with sensible defaults and can be configured through environment variables, both for native and containerized deployments.

## Environment variables

| Variable | Default value | Description |
|---|---|---|
| `HONEYPOT_PORT` | `3389` | TCP port the honeypot listens on for incoming connections. |
| `RDP_PORT` | *(alias for `HONEYPOT_PORT`)* | Alternative alias for `HONEYPOT_PORT`. |
| `DATABASE_PATH` | `data/RdpHoneypotLogs.db` | File path to the SQLite database. |
| `DB_PATH` | *(alias for `DATABASE_PATH`)* | Alternative alias for `DATABASE_PATH`. |
| `DB_ADMIN_PORT` | `8080` | Port used by Docker Compose for the `db-admin` web UI. |
| `STATIC_JPG_PATH` | `assets/desktop.jpg` | Path to the static JPG rendered to authenticated users. |
| `STATIC_IMAGE_PATH` | *(alias for `STATIC_JPG_PATH`)* | Alternative alias for `STATIC_JPG_PATH`. |
| `AUTO_BAN_RDP_CLIENTS` | `true` | Drop connections from IP addresses already logged as RDP clients. Set to `false` while testing from your own machine. |
| `ABUSEIPDB_API_KEY` | *(empty)* | AbuseIPDB APIv2 key. When set, banned `RDPClient` IPs are automatically reported to AbuseIPDB (`/api/v2/report`). |
| `ABUSEIPDB_ENABLED` | `true` | Enable or disable automatic AbuseIPDB reporting when `ABUSEIPDB_API_KEY` is configured. |
| `ABUSEIPDB_CATEGORIES` | `18,15` | Comma-separated AbuseIPDB category IDs (`18` = Brute-Force, `15` = Hacking). |
| `ABUSEIPDB_EXCLUDED_IPS` | *(empty)* | Comma-separated list of IPs to never report. Private/loopback IPs and the host's own public IP are excluded automatically. |

## Customizing the static JPG

Once an attacker authenticates (through a brute-force tool or by typing credentials into the login prompt), RDPHoney renders a static JPG to their display and disconnects them after 3 to 6 seconds.

### Default desktop

If no static JPG is provided, RDPHoney generates a Windows Server desktop image (`assets/desktop.jpg`) with a Start menu, taskbar, desktop icons, and system tray.

### Using your own image

Replace `assets/desktop.jpg` with any `.jpg`, `.jpeg`, `.png`, or `.bmp` file, or set `STATIC_JPG_PATH`:

```bash
# In .env:
STATIC_JPG_PATH=assets/my_custom_screen.jpg
```

The honeypot reads the image and scales it to match the client's screen resolution.

## Setting variables

### Docker Compose (`.env` file)

Create or edit `.env` in the repository root:

```ini
HONEYPOT_PORT=3389
DB_ADMIN_PORT=8080
DATABASE_PATH=/app/data/RdpHoneypotLogs.db
STATIC_JPG_PATH=assets/desktop.jpg
```

### Plain Docker (`docker run`)

```bash
docker run -d \
  -e HONEYPOT_PORT=3389 \
  -e DATABASE_PATH=/app/data/RdpHoneypotLogs.db \
  -p 3389:3389 \
  -v "${PWD}/data:/app/data" \
  -v "${PWD}/assets:/app/assets" \
  rdphoney:latest
```

### Windows (PowerShell)

```powershell
$env:HONEYPOT_PORT = "3389"
$env:STATIC_JPG_PATH = "C:\Honeypot\assets\desktop.jpg"
dotnet run --project RDPHoney
```