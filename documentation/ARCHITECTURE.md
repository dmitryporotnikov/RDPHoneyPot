# RDPHoney Architecture

## Overview

RDPHoney is an enhanced low-to-medium interaction RDP (Remote Desktop Protocol) honeypot written in C# targeting **.NET 10 (LTS)**. It simulates the full initial RDP connection lifecycle (MS-RDPBCGR), including TLS negotiation, GCC/MCS negotiation, licensing, capabilities exchange, graphical screen rendering, and interactive credential capture.

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

---

## Core Components

### 1. `Program.cs`
- **Application Entry Point**: Initializes the database schema, ensures static assets (`assets/desktop.jpg`) are ready, and hooks OS signals (`SIGINT`/`SIGTERM`/`ProcessExit`) for clean container termination.

### 2. `EnhancedRDPServerHoneypot.cs`
- **TCP Listener**: Listens on `IPAddress.Any` on port 3389 (configurable via `HONEYPOT_PORT`).
- **Connection Dispatcher**: Spawns a background thread per connection with a 30-second socket timeout.

### 3. `TlsCertificateManager.cs`
- **Dynamic X.509 Certificate Generation**: Generates an in-memory 2048-bit RSA self-signed TLS certificate (`CN=WIN-SRV-HONEYPOT`) on the fly using .NET 10's native cryptography API. Requires zero external tools, scripts, or OpenSSL.

### 4. `RdpPacketHelper.cs`
- **Binary PDU Construction**:
  - Builds X.224 Connection Confirm specifying `PROTOCOL_SSL` (0x01).
  - Formats ASN.1 BER-encoded GCC Conference Create Response for MCS Connect.
  - Handles MCS AttachUserConfirm and ChannelJoinConfirm for User Channel 1002 and I/O Channel 1003.
  - Constructs Server Licensing Valid Client PDU (`STATUS_VALID_CLIENT`).
  - Encodes Demand Active PDU with General, Bitmap, Order, Pointer, and Input capability sets.
  - Parses `TS_INFO_PACKET` payloads (both plain Unicode and scrambled passwords) used by automated brute-force tools (Hydra, Crowbar, Ncrack) or pre-authenticating RDP clients.
  - Decodes Fast-Path keyboard scancodes to ASCII characters.

### 5. `RdpScreenRenderer.cs`
- **Graphical Bitmap Streaming**:
  - Converts images into 24bpp BGR uncompressed format.
  - Slices images into strips of 10–16 rows to fit within Fast-Path PDU size limits (<32KB).
  - Streams strips via Fast-Path Bitmap Updates (`FASTPATH_UPDATETYPE_BITMAP`).
- **Interactive Login Screen**:
  - Generates a Windows Server lock screen with avatar, header, username/password input boxes, cursor, and helper prompts.
- **Static JPG Loading & Generation**:
  - Automatically loads `assets/desktop.jpg` or a custom file specified via `STATIC_JPG_PATH`.
  - Generates a default Windows Server desktop image (with taskbar, Start button, desktop icons, and system tray clock) if no static image is present on disk.

### 6. `DatabaseLogger.cs`
- **SQLite with WAL**: Thread-safe storage powered by `Microsoft.Data.Sqlite`.
- **Extended Fields**: Records `IPAddress`, `Timestamp` (UTC ISO 8601), `Type` (`RDPClient` vs `PortScanner`), `Username`, and `Password`.
- **Host Reachability**: Stored in `./data/RdpHoneypotLogs.db` via host volume mount.

---

## Security Model

1. **Non-Exploitable Simulation**: The honeypot does not execute arbitrary code, spawn shells, or authenticate against real system accounts.
2. **Resource Isolation**: Socket timeouts prevent resource starvation, and repeating offenders are silently dropped before consuming TLS handshake overhead.
3. **Container Isolation**: Running in Docker ensures complete separation from host operating system processes.
