# Analysis & Threat Intelligence Enrichment

Collecting honeypot telemetry is only the first step. This guide covers how to extract, analyze, and enrich RDPHoney logs using threat intelligence feeds such as AbuseIPDB.

---

## 1. Exporting Logs from the Database

To enrich your data, first export the `ConnectionLogs` table into a CSV file.

### Option A: Using the Docker Web UI (`sqlite-web`)
1. Open `http://localhost:8080` in your host browser.
2. Click on the `ConnectionLogs` table.
3. Click the **Export** button and download as CSV.

### Option B: Using `sqlite3` CLI from the Host
```bash
sqlite3 -header -csv data/RdpHoneypotLogs.db "SELECT * FROM ConnectionLogs;" > C:\temp\ConnectionLogs.csv
```

### Option C: Using DB Browser for SQLite
1. Open `data/RdpHoneypotLogs.db` in DB Browser for SQLite.
2. Go to **File -> Export -> Table(s) as CSV file...**.
3. Select `ConnectionLogs` and save to `C:\temp\ConnectionLogs.csv`.

---

## 2. Threat Intelligence Enrichment with AbuseIPDB

The repository includes a PowerShell enrichment script: `EnrichReportWithIPDB.ps1`. It queries the AbuseIPDB API for each distinct IP address in your exported CSV and attaches critical threat intelligence metrics.

### Features Added by Enrichment:
- **`abuseConfidenceScore`**: Confidence score (0–100%) indicating how likely the IP is malicious.
- **`countryCode` & `countryName`**: Geolocation of the source IP.
- **`isp` & `domain`**: Internet Service Provider and domain owner.
- **`isTor`**: Flag indicating if the connection originated from a Tor exit node.
- **`totalReports`**: Total number of abuse reports filed by the global security community.
- **`usageType`**: Type of network (Data Center / Web Hosting / Transit, Fixed Line ISP, Mobile, etc.).

### How to Run the Script

1. Obtain a free API Key from [AbuseIPDB](https://www.abuseipdb.com/register).
2. Open `EnrichReportWithIPDB.ps1` and specify your file paths and API key:
   ```powershell
   $inputCsvPath = "C:\temp\ConnectionLogs.csv"
   $outputCsvPath = "C:\temp\ConnectionLogsEnriched.csv"
   $apiKey = "YOUR_ABUSEIPDB_API_KEY_HERE"
   ```
3. Run the script in PowerShell:
   ```powershell
   .\EnrichReportWithIPDB.ps1
   ```
4. Open `C:\temp\ConnectionLogsEnriched.csv` in Excel, Google Sheets, or your SIEM for analysis and visualization.

---

## 3. SIEM & Firewall Integration Ideas

### Automatic Banning on Perimeter Firewalls
You can export all IPs classified as `RDPClient` to dynamically update firewall blocklists (e.g. `iptables`, `nftables`, pfSense, OPNsense, or AWS Network ACLs):

```bash
sqlite3 data/RdpHoneypotLogs.db "SELECT DISTINCT IPAddress FROM ConnectionLogs WHERE Type='RDPClient';" > banned_ips.txt
```

### Shipping to Elastic / Splunk / Grafana Loki
Because logs are stored with standard ISO 8601 UTC timestamps, you can configure Logstash, FluentBit, or Promtail to monitor the honeypot container logs (`docker compose logs -f rdphoney`) or ingest the SQLite database periodically.
