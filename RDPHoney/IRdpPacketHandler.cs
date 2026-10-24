using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;

namespace RDPHoney
{
    // Purpose: Implements full RDP protocol simulation:
    // - Distinguishes Port Scanners vs RDP Clients
    // - Establishes TLS handshake with self-signed certificate
    // - Exchanges MCS, Licensing, Capabilities, and Connection Finalization
    // - Captures credentials from Client Info PDU (brute-force tools) OR interactive login prompt
    // - Logs captured credentials to SQLite
    // - Renders static JPG to user's RDP display
    // - Holds for 3 to 6 seconds at random, then disconnects
    //
    // Dmitry Porotnikov

    public interface IRdpPacketHandler
    {
        void HandleClient(TcpClient client);
    }

    public class RdpConnectionHandler : IRdpPacketHandler
    {
        public static string GetClientIpAddress(TcpClient client)
        {
            if (client.Client?.RemoteEndPoint is IPEndPoint ipEndPoint)
            {
                return ipEndPoint.Address.ToString();
            }
            return "Unknown";
        }

        public static bool ShouldDropClient(string clientIP)
        {
            var env = Environment.GetEnvironmentVariable("AUTO_BAN_RDP_CLIENTS");
            if (string.Equals(env, "false", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            // Do not auto-ban loopback testing addresses
            if (IPAddress.TryParse(clientIP, out var ip) && IPAddress.IsLoopback(ip))
            {
                return false;
            }

            return DatabaseLogger.CheckIfRdpClientExists(clientIP);
        }

        public void HandleClient(TcpClient client)
        {
            string clientIP = GetClientIpAddress(client);
            if (ShouldDropClient(clientIP))
            {
                Console.WriteLine($"Connection from {clientIP} dropped due to previous RDPClient activity (auto-ban).");
                client.Close();
                return;
            }

            client.ReceiveTimeout = 30000;
            client.SendTimeout = 30000;

            using (var rawStream = client.GetStream())
            {
                try
                {
                    // 1. Read initial X.224 Connection Request
                    byte[] buffer = new byte[4096];
                    int bytesRead = rawStream.Read(buffer, 0, buffer.Length);
                    if (bytesRead < 4)
                    {
                        Console.WriteLine($"Connection closed early by {clientIP}.");
                        return;
                    }

                    // Check if packet is TPKT + X.224 CR
                    bool isX224Cr = buffer[0] == RdpProtocolConstants.TPKT_VERSION &&
                                    bytesRead >= 7 &&
                                    (buffer[5] == RdpProtocolConstants.X224_TPDU_CR || buffer[5] == 0xE0);

                    // Check for RDP Negotiation Request (0x01)
                    bool hasRdpNegReq = false;
                    uint clientRequestedProtocols = RdpProtocolConstants.PROTOCOL_SSL;
                    for (int i = 4; i <= bytesRead - 8; i++)
                    {
                        if (buffer[i] == RdpProtocolConstants.RDP_NEG_REQ && buffer[i + 2] == 0x08 && buffer[i + 3] == 0x00)
                        {
                            hasRdpNegReq = true;
                            clientRequestedProtocols = BitConverter.ToUInt32(buffer, i + 4);
                            break;
                        }
                    }

                    if (!isX224Cr || !hasRdpNegReq)
                    {
                        // Client is most likely an automated port scanner
                        SendSimplifiedPortScannerResponse(rawStream, clientIP);
                        return;
                    }

                    string cookieUsername = RdpPacketHelper.ExtractCookieUsername(buffer, 0, bytesRead);

                    // Extract client source reference from X.224 CR (bytes 8 and 9) to echo back in CC
                    ushort clientSrcRef = 0;
                    if (bytesRead >= 10)
                    {
                        clientSrcRef = (ushort)(buffer[8] | (buffer[9] << 8));
                    }

                    Console.WriteLine($"RDP Connection Request received from {clientIP} (src-ref: 0x{clientSrcRef:X4}, protocols: 0x{clientRequestedProtocols:X}). Initiating TLS negotiation...");

                    // 2. Respond with X.224 Connection Confirm specifying PROTOCOL_SSL (0x01) and echoing client's src-ref
                    byte[] ccPacket = RdpPacketHelper.BuildX224ConnectionConfirm(clientSrcRef, RdpProtocolConstants.PROTOCOL_SSL);
                    rawStream.Write(ccPacket, 0, ccPacket.Length);
                    rawStream.Flush();

                    // 3. Establish TLS Session
                    using var sslStream = new SslStream(rawStream, false);
                    try
                    {
                        var authOptions = new SslServerAuthenticationOptions
                        {
                            ServerCertificate = TlsCertificateManager.ServerCertificate,
                            ClientCertificateRequired = false,
                            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                            EnabledSslProtocols = SslProtocols.None // Allow OS to negotiate best mutually supported TLS version
                        };
                        sslStream.AuthenticateAsServer(authOptions);
                    }
                    catch (Exception tlsEx)
                    {
                        Console.WriteLine($"TLS Handshake failed with {clientIP}: {tlsEx.Message}. Logging attempt.");
                        DatabaseLogger.LogConnection(clientIP, "TLSFailed", string.IsNullOrEmpty(cookieUsername) ? null : cookieUsername, null);
                        return;
                    }

                    Console.WriteLine($"TLS Handshake established with {clientIP}. Proceeding to RDP session negotiation...");

                    // 4. MCS Connect Initial
                    int width = 1024;
                    int height = 768;
                    int bpp = 24;
                    int channelCount = 0;

                    byte[]? mcsConnectInitial = RdpPacketHelper.ReadNextPdu(sslStream);
                    if (mcsConnectInitial == null || mcsConnectInitial.Length == 0)
                    {
                        LogAndReportRdpClient(clientIP, string.IsNullOrEmpty(cookieUsername) ? null : cookieUsername, null);
                        return;
                    }

                    ExtractClientCoreAndNetInfo(mcsConnectInitial, 0, mcsConnectInitial.Length, ref width, ref height, ref bpp, ref channelCount);
                    Console.WriteLine($"Client desktop resolution: {width}x{height} ({bpp}bpp), requested channels: {channelCount}");

                    // Send MCS Connect Response echoing clientRequestedProtocols and allocated channel IDs
                    byte[] mcsResponse = RdpPacketHelper.BuildMcsConnectResponse(clientRequestedProtocols, channelCount);
                    sslStream.Write(mcsResponse, 0, mcsResponse.Length);
                    sslStream.Flush();

                    // 5. MCS ErectDomainRequest, AttachUserRequest, ChannelJoinRequests & Client Info PDU
                    bool inChannelJoin = true;
                    ushort userChannel = (ushort)(1004 + channelCount);
                    string capturedUsername = cookieUsername;
                    string capturedPassword = "";

                    while (inChannelJoin)
                    {
                        byte[]? mcsPdu = RdpPacketHelper.ReadNextPdu(sslStream);
                        if (mcsPdu == null || mcsPdu.Length == 0)
                        {
                            Console.WriteLine($"Stream closed by {clientIP} during MCS channel join phase.");
                            LogAndReportRdpClient(clientIP, string.IsNullOrEmpty(capturedUsername) ? null : capturedUsername, null);
                            return;
                        }

                        int pduOffset = FindMcsPayloadOffset(mcsPdu, mcsPdu.Length);
                        byte pduType = pduOffset >= 0 && pduOffset < mcsPdu.Length ? mcsPdu[pduOffset] : (byte)0;
                        byte mcsChoice = (byte)(pduType >> 2);

                        if (pduType == RdpProtocolConstants.MCS_ERECT_DOMAIN_REQUEST || mcsChoice == 1)
                        {
                            // MCS Erect Domain Request - no response required, proceed to next PDU
                            continue;
                        }
                        else if (pduType == RdpProtocolConstants.MCS_ATTACH_USER_REQUEST || mcsChoice == 10)
                        {
                            byte[] attachConfirm = RdpPacketHelper.BuildMcsAttachUserConfirm(userChannel);
                            sslStream.Write(attachConfirm, 0, attachConfirm.Length);
                            sslStream.Flush();
                        }
                        else if (pduType == RdpProtocolConstants.MCS_CHANNEL_JOIN_REQUEST || mcsChoice == 14)
                        {
                            ushort reqInitiator = userChannel;
                            ushort chanId = RdpProtocolConstants.MCS_IO_CHANNEL;
                            if (pduOffset + 4 < mcsPdu.Length)
                            {
                                reqInitiator = (ushort)(((mcsPdu[pduOffset + 1] << 8) | mcsPdu[pduOffset + 2]) + 1001);
                                chanId = (ushort)((mcsPdu[pduOffset + 3] << 8) | mcsPdu[pduOffset + 4]);
                                userChannel = reqInitiator;
                            }
                            byte[] joinConfirm = RdpPacketHelper.BuildMcsChannelJoinConfirm(reqInitiator, chanId);
                            sslStream.Write(joinConfirm, 0, joinConfirm.Length);
                            sslStream.Flush();
                        }
                        else if (mcsChoice == 8) // DisconnectProviderUltimatum
                        {
                            LogAndReportRdpClient(clientIP, string.IsNullOrEmpty(capturedUsername) ? null : capturedUsername, null);
                            return;
                        }
                        else
                        {
                            // MCS Send Data Request containing Client Info PDU (TS_INFO_PACKET)
                            var creds = RdpPacketHelper.ExtractCredentialsFromInfoPacket(mcsPdu, 0, mcsPdu.Length);
                            if (!string.IsNullOrEmpty(creds.username))
                            {
                                capturedUsername = creds.username;
                            }
                            if (!string.IsNullOrEmpty(creds.password))
                            {
                                capturedPassword = creds.password;
                            }
                            if (!string.IsNullOrEmpty(creds.username) || !string.IsNullOrEmpty(creds.password))
                            {
                                Console.WriteLine($"Captured Client Info PDU: User='{capturedUsername}', Domain='{creds.domain}', HasPassword={!string.IsNullOrEmpty(capturedPassword)}");
                            }

                            inChannelJoin = false;
                        }
                    }

                    // 6. Licensing Exchange
                    byte[] licenseValid = RdpPacketHelper.BuildServerLicenseValidClientPDU();
                    sslStream.Write(licenseValid, 0, licenseValid.Length);
                    sslStream.Flush();

                    // 7. Capabilities Exchange (Demand Active PDU)
                    byte[] demandActive = RdpPacketHelper.BuildDemandActivePDU(width, height, (ushort)bpp);
                    sslStream.Write(demandActive, 0, demandActive.Length);
                    sslStream.Flush();

                    // 8. Connection Finalization
                    // Wait for Client Confirm Active PDU, send Server Synchronize & Control PDUs, wait for Client Font List PDU, then send Server Font Map PDU
                    bool sentServerSyncAndControl = false;
                    try
                    {
                        sslStream.ReadTimeout = 2000;
                        DateTime finalizeDeadline = DateTime.UtcNow.AddMilliseconds(3000);
                        while (DateTime.UtcNow < finalizeDeadline)
                        {
                            byte[]? clientPdu = RdpPacketHelper.ReadNextPdu(sslStream);
                            if (clientPdu == null) break;

                            if (TryParseShareHeader(clientPdu, out ushort sharePduType, out byte sharePduType2, out int shareOffset))
                            {
                                if (sharePduType == RdpProtocolConstants.TS_PDUTYPE_CONFIRMACTIVEPDU)
                                {
                                    ExtractConfirmActiveBitmapCaps(clientPdu, shareOffset, clientPdu.Length - shareOffset, ref width, ref height, ref bpp);
                                    if (!sentServerSyncAndControl)
                                    {
                                        SendServerSyncAndControl(sslStream, userChannel);
                                        sentServerSyncAndControl = true;
                                    }
                                }
                                else if (sharePduType == RdpProtocolConstants.TS_PDUTYPE_DATAPDU &&
                                         sharePduType2 == RdpProtocolConstants.TS_PDUTYPE2_FONT_LIST)
                                {
                                    // Client Font List PDU received; finalization sequence from client is complete
                                    break;
                                }
                            }
                            else if (!sentServerSyncAndControl)
                            {
                                SendServerSyncAndControl(sslStream, userChannel);
                                sentServerSyncAndControl = true;
                            }
                        }
                    }
                    catch (IOException)
                    {
                        // Timeout waiting for optional finalization PDUs; proceed with sending remaining server finalization PDUs
                    }

                    if (!sentServerSyncAndControl)
                    {
                        SendServerSyncAndControl(sslStream, userChannel);
                    }

                    byte[] fontMapPdu = RdpPacketHelper.BuildFontMapPDU();
                    sslStream.Write(fontMapPdu, 0, fontMapPdu.Length);

                    byte[] pointerPdu = RdpPacketHelper.BuildSystemPointerPDU();
                    sslStream.Write(pointerPdu, 0, pointerPdu.Length);
                    sslStream.Flush();

                    sslStream.ReadTimeout = 30000;
                    Console.WriteLine($"RDP session established with {clientIP} ({width}x{height} @ {bpp}bpp).");

                    // 9. Credential Handling & Screen Rendering
                    if (!string.IsNullOrEmpty(capturedPassword))
                    {
                        // Case A: Credentials (including password) provided via Client Info PDU (e.g. brute force tool or saved credentials)
                        LogAndDisplayStaticJpg(sslStream, clientIP, string.IsNullOrEmpty(capturedUsername) ? "Administrator" : capturedUsername, capturedPassword, width, height, bpp);
                    }
                    else
                    {
                        // Case B: Interactive user -> Present login prompt (pre-filling username if sent), accept input, log, and render static JPG
                        HandleInteractiveLoginAndRender(sslStream, clientIP, width, height, bpp, capturedUsername);
                    }
                }
                catch (IOException ex)
                {
                    Console.WriteLine($"Network error with {clientIP}: {ex.Message}");
                    LogAndReportRdpClient(clientIP);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error handling client {clientIP}: {ex.Message}");
                }
                finally
                {
                    try { client.Close(); } catch { }
                }
            }
        }

        private static void LogAndReportRdpClient(string clientIp, string? username = null, string? password = null)
        {
            DatabaseLogger.LogConnection(clientIp, "RDPClient", username, password);
            AbuseIpDbReporter.ReportRdpClientInBackground(clientIp, username);
        }

        private static void SendServerSyncAndControl(Stream sslStream, ushort userChannel)
        {
            byte[] syncPdu = RdpPacketHelper.BuildSynchronizePDU(0x000103EA, userChannel);
            sslStream.Write(syncPdu, 0, syncPdu.Length);

            byte[] coopPdu = RdpPacketHelper.BuildControlPDU(4, 0, 0); // CTRLACTION_COOPERATE
            sslStream.Write(coopPdu, 0, coopPdu.Length);

            byte[] grantPdu = RdpPacketHelper.BuildControlPDU(2, userChannel, RdpProtocolConstants.MCS_SERVER_USER_ID); // CTRLACTION_GRANTED_CONTROL
            sslStream.Write(grantPdu, 0, grantPdu.Length);
            sslStream.Flush();
        }

        private static void SendSimplifiedPortScannerResponse(NetworkStream stream, string clientIp)
        {
            byte[] response = Encoding.ASCII.GetBytes("MCS Connect Response");
            byte[] packet = RdpPacketHelper.WrapTpktX224Data(response);

            try
            {
                stream.Write(packet, 0, packet.Length);
                stream.Flush();
            }
            catch { }

            Console.WriteLine($"Sent simplified MCS response. Peer {clientIp} classified as PortScanner.");
            DatabaseLogger.LogConnection(clientIp, "PortScanner");
        }

        private static void LogAndDisplayStaticJpg(SslStream sslStream, string clientIp, string username, string password, int width, int height, int bpp = 24)
        {
            Console.WriteLine($"[Credentials Accepted & Logged] IP: {clientIp} | User: '{username}' | Password: '{password}'");
            LogAndReportRdpClient(clientIp, username, password);

            // Render static JPG
            Console.WriteLine($"Rendering static JPG to {clientIp} ({width}x{height} @ {bpp}bpp)...");
            byte[] staticJpgRgb = RdpScreenRenderer.LoadStaticJpgRgb(width, height);
            RdpScreenRenderer.SendBitmapUpdate(sslStream, staticJpgRgb, width, height, bpp);

            // Hold session for 3 to 6 seconds at random while responding to any RefreshRect/FontList requests
            int delayMs = Random.Shared.Next(3000, 6001);
            Console.WriteLine($"Session active. Disconnecting {clientIp} in {delayMs / 1000.0:F1} seconds...");
            DateTime holdUntil = DateTime.UtcNow.AddMilliseconds(delayMs);

            try
            {
                sslStream.ReadTimeout = 500;
                while (DateTime.UtcNow < holdUntil)
                {
                    try
                    {
                        byte[]? pdu = RdpPacketHelper.ReadNextPdu(sslStream);
                        if (pdu == null) break;

                        if (TryParseShareHeader(pdu, out ushort sharePduType, out byte sharePduType2, out _))
                        {
                            if (sharePduType == RdpProtocolConstants.TS_PDUTYPE_DATAPDU &&
                                (sharePduType2 == RdpProtocolConstants.TS_PDUTYPE2_REFRESH_RECT ||
                                 sharePduType2 == RdpProtocolConstants.TS_PDUTYPE2_FONT_LIST))
                            {
                                RdpScreenRenderer.SendBitmapUpdate(sslStream, staticJpgRgb, width, height, bpp);
                            }
                        }
                    }
                    catch (IOException)
                    {
                        // Read timeout while holding session
                    }
                }
            }
            catch { }

            Console.WriteLine($"Disconnecting {clientIp}.");
        }

        private static void HandleInteractiveLoginAndRender(SslStream sslStream, string clientIp, int width, int height, int bpp = 24, string initialUsername = "")
        {
            string username = initialUsername ?? "";
            string password = "";
            bool isPasswordActive = !string.IsNullOrEmpty(username);
            bool isShift = false;

            Console.WriteLine($"Presenting graphical login prompt to {clientIp}...");

            // Render initial login screen
            byte[] loginScreenRgb = RdpScreenRenderer.GenerateLoginScreenRgb(width, height, username, password, isPasswordActive);
            RdpScreenRenderer.SendBitmapUpdate(sslStream, loginScreenRgb, width, height, bpp);

            DateTime timeout = DateTime.UtcNow.AddSeconds(60);

            while (DateTime.UtcNow < timeout)
            {
                if (!sslStream.CanRead) break;

                byte[]? pdu;
                try
                {
                    pdu = RdpPacketHelper.ReadNextPdu(sslStream);
                }
                catch (IOException)
                {
                    break;
                }

                if (pdu == null || pdu.Length == 0) break;

                bool stateChanged = false;
                bool fullRedraw = false;
                bool submitted = false;

                if (pdu[0] != RdpProtocolConstants.TPKT_VERSION &&
                    (pdu[0] & 0x03) == RdpProtocolConstants.FASTPATH_OUTPUT_ACTION_FASTPATH)
                {
                    // Fast-Path Input PDU (MS-RDPBCGR 2.2.8.1.2)
                    int numEvents = (pdu[0] >> 2) & 0x0F;
                    int offset = (pdu[1] & 0x80) != 0 ? 3 : 2;
                    if (numEvents == 0 && offset < pdu.Length)
                    {
                        numEvents = pdu[offset++];
                    }

                    for (int ev = 0; ev < numEvents && offset < pdu.Length; ev++)
                    {
                        byte eventHeader = pdu[offset++];
                        // MS-RDPBCGR 2.2.8.1.2.2: low 5 bits = eventFlags, high 3 bits = eventCode
                        byte eventFlags = (byte)(eventHeader & 0x1F);
                        byte eventCode = (byte)((eventHeader >> 5) & 0x07);
                        bool isRelease = (eventFlags & RdpProtocolConstants.FASTPATH_INPUT_KBDFLAGS_RELEASE) != 0;

                        if (eventCode == RdpProtocolConstants.FASTPATH_INPUT_EVENT_SCANCODE)
                        {
                            if (offset < pdu.Length)
                            {
                                byte scancode = pdu[offset++];
                                ProcessKeystroke(scancode, isRelease, ref username, ref password, ref isPasswordActive, ref isShift, ref stateChanged, ref submitted);
                                if (submitted) break;
                            }
                        }
                        else if (eventCode == RdpProtocolConstants.FASTPATH_INPUT_EVENT_UNICODE)
                        {
                            if (offset + 1 < pdu.Length)
                            {
                                char ch = (char)BitConverter.ToUInt16(pdu, offset);
                                offset += 2;
                                if (!isRelease && ch >= 32 && ch < 127)
                                {
                                    AppendChar(ch, ref username, ref password, isPasswordActive, ref stateChanged);
                                }
                            }
                        }
                        else if (eventCode == RdpProtocolConstants.FASTPATH_INPUT_EVENT_MOUSE ||
                                 eventCode == RdpProtocolConstants.FASTPATH_INPUT_EVENT_MOUSEX)
                        {
                            if (offset + 5 < pdu.Length)
                            {
                                ushort pointerFlags = BitConverter.ToUInt16(pdu, offset);
                                ushort mouseX = BitConverter.ToUInt16(pdu, offset + 2);
                                ushort mouseY = BitConverter.ToUInt16(pdu, offset + 4);
                                offset += 6;

                                // Left mouse click (PTRFLAGS_DOWN 0x8000 | PTRFLAGS_BUTTON1 0x1000)
                                if (eventCode == RdpProtocolConstants.FASTPATH_INPUT_EVENT_MOUSE && (pointerFlags & 0x9000) == 0x9000)
                                {
                                    HandleLoginMouseClick(width, height, mouseX, mouseY, ref isPasswordActive, ref stateChanged);
                                }
                            }
                            else
                            {
                                break;
                            }
                        }
                        else if (eventCode == RdpProtocolConstants.FASTPATH_INPUT_EVENT_SYNC)
                        {
                            offset += 1;
                        }
                        else if (eventCode == 5) // FASTPATH_INPUT_EVENT_QOE_TIMESTAMP
                        {
                            offset += 4;
                        }
                        else
                        {
                            break;
                        }
                    }
                }
                else if (pdu[0] == RdpProtocolConstants.TPKT_VERSION)
                {
                    int mcsOffset = FindMcsPayloadOffset(pdu, pdu.Length);
                    if (mcsOffset >= 0 && mcsOffset < pdu.Length && (pdu[mcsOffset] >> 2) == 8)
                    {
                        // MCS DisconnectProviderUltimatum
                        break;
                    }

                    if (TryParseShareHeader(pdu, out ushort sharePduType, out byte sharePduType2, out int shareOffset))
                    {
                        if (sharePduType == RdpProtocolConstants.TS_PDUTYPE_DATAPDU)
                        {
                            if (sharePduType2 == RdpProtocolConstants.TS_PDUTYPE2_INPUT)
                            {
                                // Slow-Path Input PDU (TS_INPUT_PDU_DATA: ShareControl(6) + ShareData(12) = 18 bytes)
                                int inputOffset = shareOffset + 18;
                                if (inputOffset + 4 <= pdu.Length)
                                {
                                    ushort numEvents = BitConverter.ToUInt16(pdu, inputOffset);
                                    int evPos = inputOffset + 4;
                                    for (int ev = 0; ev < numEvents && evPos + 12 <= pdu.Length; ev++, evPos += 12)
                                    {
                                        ushort messageType = BitConverter.ToUInt16(pdu, evPos + 4);
                                        ushort keyFlags = BitConverter.ToUInt16(pdu, evPos + 6);
                                        ushort param1 = BitConverter.ToUInt16(pdu, evPos + 8);
                                        bool isRelease = (keyFlags & 0x8000) != 0;

                                        if (messageType == 0x0004) // INPUT_EVENT_SCANCODE
                                        {
                                            ProcessKeystroke((byte)(param1 & 0xFF), isRelease, ref username, ref password, ref isPasswordActive, ref isShift, ref stateChanged, ref submitted);
                                            if (submitted) break;
                                        }
                                        else if (messageType == 0x0005 && !isRelease && param1 >= 32 && param1 < 127) // INPUT_EVENT_UNICODE
                                        {
                                            AppendChar((char)param1, ref username, ref password, isPasswordActive, ref stateChanged);
                                        }
                                        else if (messageType == 0x8001 && (keyFlags & 0x9000) == 0x9000) // INPUT_EVENT_MOUSE
                                        {
                                            ushort mouseY = BitConverter.ToUInt16(pdu, evPos + 10);
                                            HandleLoginMouseClick(width, height, param1, mouseY, ref isPasswordActive, ref stateChanged);
                                        }
                                    }
                                }
                            }
                            else if (sharePduType2 == RdpProtocolConstants.TS_PDUTYPE2_REFRESH_RECT ||
                                     sharePduType2 == RdpProtocolConstants.TS_PDUTYPE2_FONT_LIST)
                            {
                                stateChanged = true;
                                fullRedraw = true;
                            }
                        }
                    }
                }

                if (submitted)
                {
                    if (string.IsNullOrWhiteSpace(username)) username = "Administrator";
                    LogAndDisplayStaticJpg(sslStream, clientIp, username, password, width, height, bpp);
                    return;
                }

                if (stateChanged)
                {
                    byte[] updatedScreen = RdpScreenRenderer.GenerateLoginScreenRgb(width, height, username, password, isPasswordActive);
                    if (fullRedraw)
                    {
                        RdpScreenRenderer.SendBitmapUpdate(sslStream, updatedScreen, width, height, bpp);
                    }
                    else
                    {
                        int cardW = 380;
                        int cardH = 320;
                        int cardX = (width - cardW) / 2;
                        int cardY = (height - cardH) / 2;
                        RdpScreenRenderer.SendBitmapRegionUpdate(sslStream, updatedScreen, width, height, cardX + 24, cardY + 140, cardW - 48, 116, bpp);
                    }
                }
            }

            // If client disconnected or timed out without pressing Enter, still log connection and any captured username/password
            if (!string.IsNullOrEmpty(username) || !string.IsNullOrEmpty(password))
            {
                LogAndReportRdpClient(clientIp, username, string.IsNullOrEmpty(password) ? null : password);
            }
            else
            {
                LogAndReportRdpClient(clientIp);
            }
        }

        private static void ProcessKeystroke(
            byte scancode,
            bool isRelease,
            ref string username,
            ref string password,
            ref bool isPasswordActive,
            ref bool isShift,
            ref bool stateChanged,
            ref bool submitted)
        {
            if (scancode == 0x2A || scancode == 0x36) // Left or Right Shift
            {
                isShift = !isRelease;
                return;
            }

            if (isRelease)
            {
                return;
            }

            if (scancode == 0x1C) // Enter
            {
                if (!isPasswordActive && !string.IsNullOrEmpty(username))
                {
                    isPasswordActive = true;
                    stateChanged = true;
                }
                else
                {
                    submitted = true;
                }
            }
            else if (scancode == 0x0F) // Tab
            {
                isPasswordActive = !isPasswordActive;
                stateChanged = true;
            }
            else if (scancode == 0x0E) // Backspace
            {
                if (!isPasswordActive && username.Length > 0)
                {
                    username = username[..^1];
                    stateChanged = true;
                }
                else if (isPasswordActive && password.Length > 0)
                {
                    password = password[..^1];
                    stateChanged = true;
                }
            }
            else
            {
                char c = RdpPacketHelper.ScancodeToChar(scancode, isShift);
                if (c != '\0')
                {
                    AppendChar(c, ref username, ref password, isPasswordActive, ref stateChanged);
                }
            }
        }

        private static void AppendChar(char c, ref string username, ref string password, bool isPasswordActive, ref bool stateChanged)
        {
            if (!isPasswordActive && username.Length < 32)
            {
                username += c;
                stateChanged = true;
            }
            else if (isPasswordActive && password.Length < 32)
            {
                password += c;
                stateChanged = true;
            }
        }

        private static void HandleLoginMouseClick(int width, int height, ushort mouseX, ushort mouseY, ref bool isPasswordActive, ref bool stateChanged)
        {
            int cardW = 380;
            int cardH = 320;
            int cardX = (width - cardW) / 2;
            int cardY = (height - cardH) / 2;
            int inputX = cardX + 30;
            int inputW = cardW - 60;
            int inputH = 34;
            int userY = cardY + 145;
            int passY = cardY + 215;

            if (mouseX >= inputX && mouseX <= inputX + inputW)
            {
                if (mouseY >= userY - 8 && mouseY <= userY + inputH + 8 && isPasswordActive)
                {
                    isPasswordActive = false;
                    stateChanged = true;
                }
                else if (mouseY >= passY - 8 && mouseY <= passY + inputH + 8 && !isPasswordActive)
                {
                    isPasswordActive = true;
                    stateChanged = true;
                }
            }
        }

        private static bool TryParseShareHeader(byte[] pdu, out ushort pduType, out byte pduType2, out int shareOffset)
        {
            pduType = 0;
            pduType2 = 0;
            shareOffset = -1;

            int mcsOffset = FindMcsPayloadOffset(pdu, pdu.Length);
            if (mcsOffset < 0 || mcsOffset + 7 >= pdu.Length)
            {
                return false;
            }

            // MCS SendDataRequest (0x64) or SendDataIndication (0x68):
            // 1 (choice) + 2 (initiator) + 2 (channelId) + 1 (dataPriority) + 1 or 2 (PER length)
            byte mcsChoice = (byte)(pdu[mcsOffset] >> 2);
            if (mcsChoice != 25 && mcsChoice != 26)
            {
                return false;
            }

            int perLenPos = mcsOffset + 6;
            int userDataOffset = (pdu[perLenPos] & 0x80) != 0 ? perLenPos + 2 : perLenPos + 1;

            if (userDataOffset + 6 > pdu.Length)
            {
                return false;
            }

            // Check if a 4-byte Basic Security Header (flags == 0x0000) precedes ShareControlHeader
            ushort rawPduType = BitConverter.ToUInt16(pdu, userDataOffset + 2);
            if ((rawPduType & 0x000F) != 0x0001 && (rawPduType & 0x000F) != 0x0003 && (rawPduType & 0x000F) != 0x0007 &&
                userDataOffset + 10 <= pdu.Length)
            {
                ushort altPduType = BitConverter.ToUInt16(pdu, userDataOffset + 4 + 2);
                if ((altPduType & 0x000F) == 0x0001 || (altPduType & 0x000F) == 0x0003 || (altPduType & 0x000F) == 0x0007)
                {
                    userDataOffset += 4;
                    rawPduType = altPduType;
                }
            }

            shareOffset = userDataOffset;
            pduType = rawPduType;

            if (pduType == RdpProtocolConstants.TS_PDUTYPE_DATAPDU && shareOffset + 18 <= pdu.Length)
            {
                pduType2 = pdu[shareOffset + 14];
            }

            return true;
        }

        private static int FindMcsPayloadOffset(byte[] buffer, int length)
        {
            if (length >= 7 && buffer[0] == RdpProtocolConstants.TPKT_VERSION && buffer[5] == RdpProtocolConstants.X224_TPDU_DT)
            {
                return 7;
            }
            return -1;
        }

        private static void ExtractClientCoreAndNetInfo(byte[] buffer, int offset, int length, ref int width, ref int height, ref int bpp, ref int channelCount)
        {
            try
            {
                int end = offset + length;
                for (int i = offset; i <= end - 8; i++)
                {
                    // CS_CORE type = 0xC001
                    if (buffer[i] == 0x01 && buffer[i + 1] == 0xC0 && i + 16 <= end)
                    {
                        ushort blockLen = BitConverter.ToUInt16(buffer, i + 2);
                        if (blockLen >= 16 && blockLen <= 512 && i + blockLen <= end)
                        {
                            ushort w = BitConverter.ToUInt16(buffer, i + 8);
                            ushort h = BitConverter.ToUInt16(buffer, i + 10);
                            if (w >= 320 && h >= 200)
                            {
                                // Cap resolution to 1920x1080 to prevent memory exhaustion DoS from spoofed dimensions
                                int clampedW = Math.Min((int)w, 1920);
                                int clampedH = Math.Min((int)h, 1080);
                                width = (clampedW / 4) * 4;
                                height = clampedH;
                            }

                            ushort colorDepth = BitConverter.ToUInt16(buffer, i + 12);
                            if (colorDepth == 0xCA02) bpp = 15;
                            else if (colorDepth == 0xCA03) bpp = 16;
                            else if (colorDepth == 0xCA04) bpp = 24;

                            if (blockLen >= 138 && i + 138 <= end)
                            {
                                ushort highColorDepth = BitConverter.ToUInt16(buffer, i + 136);
                                if (highColorDepth == 15 || highColorDepth == 16 || highColorDepth == 24)
                                {
                                    bpp = highColorDepth;
                                }
                            }
                        }
                    }
                    // CS_NET type = 0xC003
                    else if (buffer[i] == 0x03 && buffer[i + 1] == 0xC0 && i + 8 <= end)
                    {
                        ushort blockLen = BitConverter.ToUInt16(buffer, i + 2);
                        uint chCount = BitConverter.ToUInt32(buffer, i + 4);
                        if (chCount <= 31 && blockLen == 8 + chCount * 12 && i + blockLen <= end)
                        {
                            channelCount = (int)chCount;
                        }
                    }
                }
            }
            catch { }
        }

        private static void ExtractConfirmActiveBitmapCaps(byte[] buffer, int offset, int length, ref int width, ref int height, ref int bpp)
        {
            try
            {
                // ConfirmActivePDU: ShareControlHeader (6) + shareId (4) + originatorId (2) + lengthSourceDescriptor (2) + lengthCombinedCapabilities (2)
                if (length < 20) return;
                int end = offset + length;
                ushort lenSrcDesc = BitConverter.ToUInt16(buffer, offset + 12);
                int capsStart = offset + 16 + lenSrcDesc;
                if (capsStart + 4 > end) return;

                ushort numCaps = BitConverter.ToUInt16(buffer, capsStart);
                int pos = capsStart + 4;

                for (int c = 0; c < numCaps && pos + 4 <= end; c++)
                {
                    ushort capType = BitConverter.ToUInt16(buffer, pos);
                    ushort capLen = BitConverter.ToUInt16(buffer, pos + 2);
                    if (capLen < 4 || pos + capLen > end) break;

                    if (capType == 0x0002 && capLen >= 16) // CAPSTYPE_BITMAP
                    {
                        ushort prefBpp = BitConverter.ToUInt16(buffer, pos + 4);
                        ushort w = BitConverter.ToUInt16(buffer, pos + 12);
                        ushort h = BitConverter.ToUInt16(buffer, pos + 14);

                        if (prefBpp == 15 || prefBpp == 16 || prefBpp == 24 || prefBpp == 32)
                        {
                            bpp = prefBpp;
                        }
                        if (w >= 320 && h >= 200)
                        {
                            int clampedW = Math.Min((int)w, 1920);
                            int clampedH = Math.Min((int)h, 1080);
                            width = (clampedW / 4) * 4;
                            height = clampedH;
                        }
                    }

                    pos += capLen;
                }
            }
            catch { }
        }
    }
}
