# Database Guide

This document describes the RDPHoney database structure, schema, credential tracking, and multiple methods for the administrator to access and interact with the database from the host machine.

---

## Database Overview

- **Engine**: SQLite 3 (powered by `Microsoft.Data.Sqlite` on .NET 10 LTS)
- **Default Host Location**: `./data/RdpHoneypotLogs.db`
- **Container Path**: `/app/data/RdpHoneypotLogs.db`
- **Journal Mode**: `WAL` (Write-Ahead Logging) for safe concurrent reads from the host

---

## Schema Definition

The honeypot automatically creates and migrates the table on startup:

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

### Column Descriptions

| Column | Data Type | Nullable | Description | Example |
|---|---|---|---|---|
| `Id` | INTEGER | No | Auto-incrementing primary key | `1` |
| `IPAddress` | TEXT | No | Source IPv4 or IPv6 address | `198.51.100.25` |
| `Timestamp` | TEXT | No | UTC timestamp in ISO 8601 format | `2026-09-27 10:15:30.1234567Z` |
| `Type` | TEXT | No | Classification (`RDPClient` or `PortScanner`) | `RDPClient` |
| `Username` | TEXT | Yes | Captured username (from login prompt or Client Info PDU) | `administrator` |
| `Password` | TEXT | Yes | Captured password submitted by the attacker | `P@ssw0rd2026!` |

---

## How Administrators Can Interact from Host Machine

Because `./data` is mounted to the host machine and WAL mode is active:

### Method 1: DB Browser for SQLite (Host GUI)
1. Launch **DB Browser for SQLite** on the host.
2. Open `./data/RdpHoneypotLogs.db`.
3. Under the **Browse Data** tab, inspect incoming connections, usernames, and passwords in real-time.

### Method 2: Web UI via Docker Compose (`http://localhost:8080`)
1. Open your browser on the host to:
   ```text
   http://localhost:8080
   ```
2. View rows, filter by `Username` or `Type`, run custom queries, and export results directly to CSV.

### Method 3: Command-Line (`sqlite3`)
```bash
# View captured credentials
sqlite3 -header -column data/RdpHoneypotLogs.db \
  "SELECT Id, IPAddress, Timestamp, Username, Password FROM ConnectionLogs WHERE Username IS NOT NULL;"
```

---

## Threat Hunting & Analysis Queries

### 1. View All Captured Credentials
```sql
SELECT Id, IPAddress, Timestamp, Username, Password
FROM ConnectionLogs
WHERE Username IS NOT NULL OR Password IS NOT NULL
ORDER BY Id DESC;
```

### 2. Top Targeted Usernames
```sql
SELECT Username, COUNT(*) AS Attempts
FROM ConnectionLogs
WHERE Username IS NOT NULL
GROUP BY Username
ORDER BY Attempts DESC
LIMIT 10;
```

### 3. Top Attacking IPs with Passwords Attempted
```sql
SELECT IPAddress, COUNT(*) AS TotalAttempts, 
       GROUP_CONCAT(DISTINCT Username) AS UsernamesTried
FROM ConnectionLogs
WHERE Username IS NOT NULL
GROUP BY IPAddress
ORDER BY TotalAttempts DESC;
```

### 4. Breakdown by Connection Type
```sql
SELECT Type, COUNT(*) AS Count,
       ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM ConnectionLogs), 2) AS Percentage
FROM ConnectionLogs
GROUP BY Type;
```
