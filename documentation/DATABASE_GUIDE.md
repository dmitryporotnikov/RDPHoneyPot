# Database guide

The RDPHoney database structure, schema, credential tracking, and the ways an administrator can access the database from the host machine.

## Database overview

- Engine: SQLite 3 (through `Microsoft.Data.Sqlite` on .NET 10 LTS)
- Default host location: `./data/RdpHoneypotLogs.db`
- Container path: `/app/data/RdpHoneypotLogs.db`
- Journal mode: `WAL` (Write-Ahead Logging), which allows safe concurrent reads from the host

## Schema definition

The honeypot creates and migrates the table on startup:

```sql
CREATE TABLE IF NOT EXISTS ConnectionLogs (
    Id INTEGER PRIMARY KEY AUTOINCREMENT,
    IPAddress TEXT NOT NULL,
    Timestamp TEXT NOT NULL,
    Type TEXT NOT NULL,
    Username TEXT NULL,
    Password TEXT NULL
);

CREATE INDEX IF NOT EXISTS IX_ConnectionLogs_IPAddress_Type 
    ON ConnectionLogs (IPAddress, Type);
```

### Column descriptions

| Column | Data type | Nullable | Description | Example |
|---|---|---|---|---|
| `Id` | INTEGER | No | Auto-incrementing primary key | `1` |
| `IPAddress` | TEXT | No | Source IPv4 or IPv6 address | `198.51.100.25` |
| `Timestamp` | TEXT | No | UTC timestamp in ISO 8601 format | `2026-09-27 10:15:30.1234567Z` |
| `Type` | TEXT | No | Classification (`RDPClient` or `PortScanner`) | `RDPClient` |
| `Username` | TEXT | Yes | Captured username (from the login prompt or Client Info PDU) | `administrator` |
| `Password` | TEXT | Yes | Password submitted by the attacker | `P@ssw0rd2026!` |

## Accessing the database from the host

`./data` is mounted to the host and WAL mode is active, so there are several ways to work with the database:

### Method 1: DB Browser for SQLite (host GUI)

1. Launch DB Browser for SQLite on the host.
2. Open `./data/RdpHoneypotLogs.db`.
3. Under the Browse Data tab, inspect incoming connections, usernames, and passwords in real time.

### Method 2: Web UI through Docker Compose (`http://localhost:8080`)

1. Open a browser on the host to:

   ```text
   http://localhost:8080
   ```

2. View rows, filter by `Username` or `Type`, run custom queries, and export results to CSV.

### Method 3: Command line (`sqlite3`)

```bash
# View captured credentials
sqlite3 -header -column data/RdpHoneypotLogs.db \
  "SELECT Id, IPAddress, Timestamp, Username, Password FROM ConnectionLogs WHERE Username IS NOT NULL;"
```

## Threat hunting and analysis queries

### All captured credentials

```sql
SELECT Id, IPAddress, Timestamp, Username, Password
FROM ConnectionLogs
WHERE Username IS NOT NULL OR Password IS NOT NULL
ORDER BY Id DESC;
```

### Top targeted usernames

```sql
SELECT Username, COUNT(*) AS Attempts
FROM ConnectionLogs
WHERE Username IS NOT NULL
GROUP BY Username
ORDER BY Attempts DESC
LIMIT 10;
```

### Top attacking IPs with usernames attempted

```sql
SELECT IPAddress, COUNT(*) AS TotalAttempts, 
       GROUP_CONCAT(DISTINCT Username) AS UsernamesTried
FROM ConnectionLogs
WHERE Username IS NOT NULL
GROUP BY IPAddress
ORDER BY TotalAttempts DESC;
```

### Breakdown by connection type

```sql
SELECT Type, COUNT(*) AS Count,
       ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM ConnectionLogs), 2) AS Percentage
FROM ConnectionLogs
GROUP BY Type;
```