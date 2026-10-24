# RDPHoney architecture

RDPHoney is a low-to-medium interaction RDP (Remote Desktop Protocol) honeypot written in C# on .NET 10 (LTS). It simulates the initial RDP connection lifecycle (MS-RDPBCGR) end to end: TLS negotiation, GCC/MCS negotiation, licensing, capabilities exchange, graphical screen rendering, and interactive credential capture.

```
                      +-----------------------------+
                      |   Incoming TCP Connection   |
                      +--------------+--------------+
                                     |
                                     v
                      +-----------------------------+
                      |  RdpConnectionHandler       |
                      |  Check: IP already banned?  |
                      +--------------+--------------+
                                     |
                     +---------------+---------------+
                     |                               |
              [Already Logged as              [New IP Address]
                 RDPClient]                          |
                     |                               v
                     v                      +------------------+
              Drop Connection               | Read X.224 CR    |
              Silently                      +--------+---------+
                                                     |
                                     +---------------+---------------+
                                     |                               |
                             [No RDP Neg Req]                 [RDP Neg Req]
                             (Port Scanner)                   (Real Client)
                                     |                               |
                                     v                               v
                            +-----------------+             +------------------+
                            | Simplified MCS  |             | Send X.224 CC    |
                            | Response & Log  |             | (PROTOCOL_SSL)   |
                            |  PortScanner    |             +--------+---------+
                            +-----------------+                      |
                                                                     v
                                                            +------------------+
                                                            |  TLS Handshake   |
                                                            | (Self-Signed X509|
                                                            +--------+---------+
                                                                     |
                                                                     v
                                                            +------------------+
                                                            | MCS Connect &    |
                                                            | User/Channel Join|
                                                            +--------+---------+
                                                                     |
                                                                     v
                                                            +------------------+
                                                            | Client Info PDU  |
                                                            | (TS_INFO_PACKET) |
                                                            +--------+---------+
                                                                     |
                                                     +---------------+---------------+
                                                     |                               |
                                            [Credentials in                 [Empty Credentials]
                                             TS_INFO_PACKET]                         |
                                                     |                               v
                                                     |                      +------------------+
                                                     |                      | Licensing & Caps |
                                                     |                      | Demand/Confirm   |
                                                     |                      +--------+---------+
                                                     |                               |
                                                     |                               v
                                                     |                      +------------------+
                                                     |                      | Render Graphical |
                                                     |                      |   Login Prompt   |
                                                     |                      +--------+---------+
                                                     |                               |
                                                     |                               v
                                                     |                      +------------------+
                                                     |                      | Capture Keyboard |
                                                     |                      | (Fast-Path Input)|
                                                     |                      |  User submits    |
                                                     |                      +--------+---------+
                                                     |                               |
                                                     +---------------+---------------+
                                                                     |
                                                                     v
                                                            +------------------+
                                                            | Accept & Log to  |
                                                            | Database (SQLite)|
                                                            |  User & Password |
                                                            +--------+---------+
                                                                     |
                                                                     v
                                                            +------------------+
                                                            | Render Static JPG|
                                                            | (Fast-Path Bitmap|
                                                            +--------+---------+
                                                                     |
                                                                     v
                                                            +------------------+
                                                            | Hold 3-6 Seconds |
                                                            |  (Random Delay)  |
                                                            +--------+---------+
                                                                     |
                                                                     v
                                                            +------------------+
                                                            | Disconnect Client|
                                                            +------------------+
```

## Core components

### Program.cs

The application entry point. Initializes the database schema, makes sure the static assets (`assets/desktop.jpg`) are in place, and hooks OS signals (`SIGINT`, `SIGTERM`, `ProcessExit`) for clean container termination.

### EnhancedRDPServerHoneypot.cs

The TCP listener is bound to `IPAddress.Any` on port 3389 (configurable through `HONEYPOT_PORT`). The connection dispatcher spawns a background thread per connection with a 30-second socket timeout.

### TlsCertificateManager.cs

Generates an in-memory 2048-bit RSA self-signed TLS certificate (`CN=WIN-SRV-HONEYPOT`) on the fly with .NET's native cryptography API. No external tools, scripts, or OpenSSL needed.

### RdpPacketHelper.cs

Binary PDU construction:

- Builds the X.224 Connection Confirm specifying `PROTOCOL_SSL` (0x01).
- Formats the ASN.1 BER-encoded GCC Conference Create Response for MCS Connect.
- Handles MCS AttachUserConfirm and ChannelJoinConfirm for User Channel 1002 and I/O Channel 1003.
- Constructs the Server Licensing Valid Client PDU (`STATUS_VALID_CLIENT`).
- Encodes the Demand Active PDU with General, Bitmap, Order, Pointer, and Input capability sets.
- Parses `TS_INFO_PACKET` payloads, in both plain Unicode and scrambled-password forms, as used by automated brute-force tools (Hydra, Crowbar, Ncrack) and by RDP clients that pre-authenticate.
- Decodes Fast-Path keyboard scancodes to ASCII characters.

### RdpScreenRenderer.cs

Graphical bitmap streaming:

- Converts images to 24bpp BGR uncompressed format.
- Slices images into strips of 10 to 16 rows to fit within Fast-Path PDU size limits (under 32KB).
- Streams the strips via Fast-Path Bitmap Updates (`FASTPATH_UPDATETYPE_BITMAP`).

Interactive login screen: draws a Windows Server lock screen with avatar, header, username/password input boxes, cursor, and helper prompts.

Static JPG loading and generation: loads `assets/desktop.jpg` or the file set through `STATIC_JPG_PATH`. If no static image exists on disk, it generates a default Windows Server desktop image (taskbar, Start button, desktop icons, system tray clock).

### DatabaseLogger.cs

Thread-safe SQLite storage through `Microsoft.Data.Sqlite`, running in WAL mode. Each row records `IPAddress`, `Timestamp` (UTC ISO 8601), `Type` (`RDPClient`, `PortScanner`, or `TLSFailed`), `Username`, `Password`, `ReportedToAbuseIPDB`, and `AbuseConfidenceScore`. The database is stored in `./data/RdpHoneypotLogs.db` through a host volume mount, so it is reachable from the host machine.

### AbuseIpDbReporter.cs

Automatic threat-intelligence reporting to AbuseIPDB APIv2 (`/api/v2/report`) and IP reputation lookup (`/api/v2/check`). When `ABUSEIPDB_API_KEY` is configured, any IP classified and banned as `RDPClient` is reported in the background with categories `18,15` (Brute-Force, Hacking). Built-in safeguards ensure loopback, private RFC 1918, link-local, CGNAT, `ABUSEIPDB_EXCLUDED_IPS`, and the host's own public IP (`api.ipify.org`) are never reported, and enforce a 15-minute per-IP reporting cooldown.

## Security model

1. **No Shell or OS Authentication Execution:** The honeypot is a pure protocol state-machine simulation. It never spawns processes, never loads a real desktop or shell, ignores virtual channel payloads (`rdpdr`, `cliprdr`, etc.), and never calls OS authentication APIs.
2. **DoS & Memory Hardening:** Concurrent sessions are bounded by a `SemaphoreSlim` (`MAX_CONCURRENT_CONNECTIONS`, default `64`), client framebuffer dimensions are clamped to a maximum of `1920x1080`, the static desktop JPG is cached in memory, socket operations enforce timeouts, and repeat offenders are dropped before the TLS handshake.
3. **Container & Admin UI Lockdown:** Both containers run with `no-new-privileges:true`, `cap_drop: [ALL]`, and memory limits. The `sqlite-web` admin console (`db-admin`) runs in read-only mode (`-r`) and binds strictly to `127.0.0.1:8080` so it is never exposed to the public internet.