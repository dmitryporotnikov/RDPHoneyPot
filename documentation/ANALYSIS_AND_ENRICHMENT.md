# Analysis, auto-reporting, and threat intelligence enrichment

Collecting honeypot telemetry is the first step. This guide covers automatic AbuseIPDB reporting of banned RDP clients as well as exporting, analyzing, and enriching RDPHoney logs offline.

## 0. Real-time automatic AbuseIPDB reporting

RDPHoney can automatically report every attacker IP that completes an RDP handshake (`Type = 'RDPClient'`) to the [AbuseIPDB APIv2 `/report` endpoint](https://docs.abuseipdb.com/#report-endpoint) as soon as the IP is logged and banned:

1. Set `ABUSEIPDB_API_KEY` in `.env` or your container environment:

   ```ini
   ABUSEIPDB_API_KEY=your_abuseipdb_api_v2_key
   ABUSEIPDB_ENABLED=true
   ABUSEIPDB_CATEGORIES=18,15
   ABUSEIPDB_EXCLUDED_IPS=
   ```

2. When an attacker connects via RDP, RDPHoney:
   - Logs the attempt and credentials in SQLite (`ConnectionLogs`).
   - Checks that the IP is a valid public IP (automatically excluding loopback, RFC 1918 private, Docker bridge, CGNAT, link-local, `ABUSEIPDB_EXCLUDED_IPS`, and the host's own public IP resolved via `api.ipify.org`).
   - Verifies the IP has not already been reported within the last 15 minutes.
   - Submits a report to `https://api.abuseipdb.com/api/v2/report` with categories `18,15` (Brute-Force, Hacking) and records `ReportedToAbuseIPDB = 1` and the returned `AbuseConfidenceScore` in SQLite.

## 1. Exporting logs from the database

To enrich the data, first export the `ConnectionLogs` table to a CSV file.

### Option A: Docker web UI (`sqlite-web`)

1. Open `http://localhost:8080` in the host browser.
2. Click the `ConnectionLogs` table.
3. Click Export and download as CSV.

### Option B: `sqlite3` CLI from the host

```bash
sqlite3 -header -csv data/RdpHoneypotLogs.db "SELECT * FROM ConnectionLogs;" > C:\temp\ConnectionLogs.csv
```

### Option C: DB Browser for SQLite

1. Open `data/RdpHoneypotLogs.db` in DB Browser for SQLite.
2. Go to File -> Export -> Table(s) as CSV file.
3. Select `ConnectionLogs` and save to `C:\temp\ConnectionLogs.csv`.

## 2. Threat intelligence enrichment with AbuseIPDB

The repository includes a PowerShell enrichment script, `EnrichReportWithIPDB.ps1`. It queries the AbuseIPDB API for each distinct IP address in the exported CSV and attaches the following threat intelligence fields:

- `abuseConfidenceScore`: confidence score (0 to 100%) of how likely the IP is to be malicious.
- `countryCode` and `countryName`: geolocation of the source IP.
- `isp` and `domain`: internet service provider and domain owner.
- `isTor`: flag indicating whether the connection originated from a Tor exit node.
- `totalReports`: number of abuse reports filed by the security community.
- `usageType`: network type (data center / web hosting / transit, fixed line ISP, mobile, etc.).

### Running the script

1. Get a free API key from [AbuseIPDB](https://www.abuseipdb.com/register).
2. Open `EnrichReportWithIPDB.ps1` and set the file paths and API key:

   ```powershell
   $inputCsvPath = "C:\temp\ConnectionLogs.csv"
   $outputCsvPath = "C:\temp\ConnectionLogsEnriched.csv"
   $apiKey = "YOUR_ABUSEIPDB_API_KEY_HERE"
   ```

3. Run the script in PowerShell:

   ```powershell
   .\EnrichReportWithIPDB.ps1
   ```

4. Open `C:\temp\ConnectionLogsEnriched.csv` in Excel, Google Sheets, or your SIEM for analysis.

## 3. SIEM and firewall integration ideas

### Automatic banning on perimeter firewalls

Export all IPs classified as `RDPClient` to update firewall blocklists (`iptables`, `nftables`, pfSense, OPNsense, or AWS Network ACLs):

```bash
sqlite3 data/RdpHoneypotLogs.db "SELECT DISTINCT IPAddress FROM ConnectionLogs WHERE Type='RDPClient';" > banned_ips.txt
```

### Shipping to Elastic, Splunk, or Grafana Loki

Logs use standard ISO 8601 UTC timestamps, so Logstash, FluentBit, or Promtail can either monitor the honeypot container logs (`docker compose logs -f rdphoney`) or ingest the SQLite database periodically.