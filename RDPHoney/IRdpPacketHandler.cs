using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
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

        public void HandleClient(TcpClient client)
        {
            string clientIP = GetClientIpAddress(client);
            if (DatabaseLogger.CheckIfRdpClientExists(clientIP))
            {
                Console.WriteLine($"Connection from {clientIP} dropped due to previous RDPClient activity.");
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
                    for (int i = 4; i < bytesRead - 7; i++)
                    {
                        if (buffer[i] == RdpProtocolConstants.RDP_NEG_REQ && buffer[i + 2] == 0x08)
                        {
                            hasRdpNegReq = true;
                            break;
                        }
                    }

                    if (!isX224Cr || !hasRdpNegReq)
                    {
                        // Client is most likely an automated port scanner
                        SendSimplifiedPortScannerResponse(rawStream, clientIP);
                        return;
                    }

                    Console.WriteLine($"RDP Connection Request received from {clientIP}. Initiating TLS negotiation...");

                    // 2. Respond with X.224 Connection Confirm specifying PROTOCOL_SSL (0x01)
                    byte[] ccPacket = RdpPacketHelper.BuildX224ConnectionConfirm(0x1234, RdpProtocolConstants.PROTOCOL_SSL);
                    rawStream.Write(ccPacket, 0, ccPacket.Length);
                    rawStream.Flush();

                    // 3. Establish TLS Session
                    using var sslStream = new SslStream(rawStream, false);
                    try
                    {
                        sslStream.AuthenticateAsServer(
                            TlsCertificateManager.ServerCertificate,
                            clientCertificateRequired: false,
                            enabledSslProtocols: SslProtocols.Tls12 | SslProtocols.Tls13,
                            checkCertificateRevocation: false);
                    }
                    catch (Exception tlsEx)
                    {
                        Console.WriteLine($"TLS Handshake failed with {clientIP}: {tlsEx.Message}. Logging as RDPClient.");
                        DatabaseLogger.LogConnection(clientIP, "RDPClient");
                        return;
                    }

                    Console.WriteLine($"TLS Handshake established with {clientIP}. Proceeding to RDP session negotiation...");

                    // 4. MCS Connect Initial
                    int width = 1024;
                    int height = 768;
                    byte[] mcsBuffer = new byte[8192];
                    int mcsBytes = sslStream.Read(mcsBuffer, 0, mcsBuffer.Length);

                    if (mcsBytes > 0)
                    {
                        ExtractClientResolution(mcsBuffer, 0, mcsBytes, ref width, ref height);
                        Console.WriteLine($"Client desktop resolution: {width}x{height}");
                    }

                    // Send MCS Connect Response
                    byte[] mcsResponse = RdpPacketHelper.BuildMcsConnectResponse();
                    sslStream.Write(mcsResponse, 0, mcsResponse.Length);
                    sslStream.Flush();

                    // 5. MCS AttachUserRequest & ChannelJoinRequests
                    bool inChannelJoin = true;
                    ushort userChannel = RdpProtocolConstants.MCS_USERCHANNEL_BASE;
                    string capturedUsername = "";
                    string capturedPassword = "";

                    while (inChannelJoin)
                    {
                        int len = sslStream.Read(mcsBuffer, 0, mcsBuffer.Length);
                        if (len <= 0) break;

                        // Check PDU type
                        int pduOffset = FindMcsPayloadOffset(mcsBuffer, len);
                        byte pduType = pduOffset >= 0 ? mcsBuffer[pduOffset] : (byte)0;

                        if (pduType == RdpProtocolConstants.MCS_ATTACH_USER_REQUEST || (len >= 8 && mcsBuffer[7] == 0x28))
                        {
                            byte[] attachConfirm = RdpPacketHelper.BuildMcsAttachUserConfirm(userChannel);
                            sslStream.Write(attachConfirm, 0, attachConfirm.Length);
                            sslStream.Flush();
                        }
                        else if (pduType == RdpProtocolConstants.MCS_CHANNEL_JOIN_REQUEST || (len >= 8 && mcsBuffer[7] == 0x38))
                        {
                            // Extract requested channel ID
                            ushort chanId = 1003;
                            if (pduOffset + 4 < len)
                            {
                                chanId = (ushort)((mcsBuffer[pduOffset + 3] << 8) | mcsBuffer[pduOffset + 4]);
                            }
                            byte[] joinConfirm = RdpPacketHelper.BuildMcsChannelJoinConfirm(userChannel, chanId);
                            sslStream.Write(joinConfirm, 0, joinConfirm.Length);
                            sslStream.Flush();
                        }
                        else
                        {
                            // Check for Client Info PDU (TS_INFO_PACKET)
                            var creds = RdpPacketHelper.ExtractCredentialsFromInfoPacket(mcsBuffer, 0, len);
                            if (!string.IsNullOrEmpty(creds.username))
                            {
                                capturedUsername = creds.username;
                                capturedPassword = creds.password;
                                Console.WriteLine($"Captured credentials in Client Info PDU: User='{capturedUsername}', Domain='{creds.domain}'");
                            }

                            inChannelJoin = false;
                        }
                    }

                    // 6. Licensing Exchange
                    byte[] licenseValid = RdpPacketHelper.BuildServerLicenseValidClientPDU();
                    sslStream.Write(licenseValid, 0, licenseValid.Length);
                    sslStream.Flush();

                    // 7. Capabilities Exchange (Demand Active PDU)
                    byte[] demandActive = RdpPacketHelper.BuildDemandActivePDU(width, height);
                    sslStream.Write(demandActive, 0, demandActive.Length);
                    sslStream.Flush();

                    // Read Confirm Active PDU & Client Synchronize
                    _ = sslStream.Read(mcsBuffer, 0, mcsBuffer.Length);

                    // 8. Connection Finalization (Synchronize, Control Cooperate, Granted Control, Font Map)
                    byte[] syncPdu = RdpPacketHelper.BuildSynchronizePDU();
                    sslStream.Write(syncPdu, 0, syncPdu.Length);

                    byte[] coopPdu = RdpPacketHelper.BuildControlPDU(4); // CTRLACTION_COOPERATE
                    sslStream.Write(coopPdu, 0, coopPdu.Length);

                    byte[] grantPdu = RdpPacketHelper.BuildControlPDU(2, userChannel, RdpProtocolConstants.MCS_IO_CHANNEL); // CTRLACTION_GRANTED_CONTROL
                    sslStream.Write(grantPdu, 0, grantPdu.Length);

                    byte[] fontMapPdu = RdpPacketHelper.BuildFontMapPDU();
                    sslStream.Write(fontMapPdu, 0, fontMapPdu.Length);
                    sslStream.Flush();

                    Console.WriteLine($"RDP session established with {clientIP}.");

                    // 9. Credential Handling & Screen Rendering
                    if (!string.IsNullOrEmpty(capturedUsername) || !string.IsNullOrEmpty(capturedPassword))
                    {
                        // Case A: Credentials provided via Client Info PDU (e.g. brute force tool or saved credentials)
                        LogAndDisplayStaticJpg(sslStream, clientIP, capturedUsername, capturedPassword, width, height);
                    }
                    else
                    {
                        // Case B: Interactive user -> Present login prompt, accept input, log, and render static JPG
                        HandleInteractiveLoginAndRender(sslStream, clientIP, width, height);
                    }
                }
                catch (IOException ex)
                {
                    Console.WriteLine($"Network error with {clientIP}: {ex.Message}");
                    DatabaseLogger.LogConnection(clientIP, "RDPClient");
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

        private static void LogAndDisplayStaticJpg(SslStream sslStream, string clientIp, string username, string password, int width, int height)
        {
            Console.WriteLine($"[Credentials Accepted & Logged] IP: {clientIp} | User: '{username}' | Password: '{password}'");
            DatabaseLogger.LogConnection(clientIp, "RDPClient", username, password);

            // Render static JPG
            Console.WriteLine($"Rendering static JPG to {clientIp}...");
            byte[] staticJpgRgb = RdpScreenRenderer.LoadStaticJpgRgb(width, height);
            RdpScreenRenderer.SendBitmapUpdate(sslStream, staticJpgRgb, width, height);

            // Hold session for 3 to 6 seconds at random
            int delayMs = Random.Shared.Next(3000, 6001);
            Console.WriteLine($"Session active. Disconnecting {clientIp} in {delayMs / 1000.0:F1} seconds...");
            Thread.Sleep(delayMs);
            Console.WriteLine($"Disconnecting {clientIp}.");
        }

        private static void HandleInteractiveLoginAndRender(SslStream sslStream, string clientIp, int width, int height)
        {
            string username = "";
            string password = "";
            bool isPasswordActive = false;
            bool isShift = false;

            Console.WriteLine($"Presenting graphical login prompt to {clientIp}...");

            // Render initial login screen
            byte[] loginScreenRgb = RdpScreenRenderer.GenerateLoginScreenRgb(width, height, username, password, isPasswordActive);
            RdpScreenRenderer.SendBitmapUpdate(sslStream, loginScreenRgb, width, height);

            byte[] inputBuffer = new byte[2048];
            DateTime timeout = DateTime.UtcNow.AddSeconds(60);

            while (DateTime.UtcNow < timeout)
            {
                if (!sslStream.CanRead) break;

                int bytesRead = sslStream.Read(inputBuffer, 0, inputBuffer.Length);
                if (bytesRead <= 0) break;

                bool stateChanged = false;
                bool submitted = false;

                // Parse input events
                for (int i = 0; i < bytesRead; i++)
                {
                    // Check for Fast-Path Input event (0x00 header or 0x03)
                    byte header = inputBuffer[i];
                    if ((header & 0x03) == RdpProtocolConstants.FASTPATH_OUTPUT_ACTION_FASTPATH && i + 3 < bytesRead)
                    {
                        byte eventHeader = inputBuffer[i + 2];
                        byte eventCode = (byte)(eventHeader & 0x1F);
                        byte eventFlags = (byte)((eventHeader >> 5) & 0x07);
                        bool isRelease = (eventFlags & RdpProtocolConstants.FASTPATH_INPUT_KBDFLAGS_RELEASE) != 0;

                        if (eventCode == RdpProtocolConstants.FASTPATH_INPUT_EVENT_SCANCODE && i + 3 < bytesRead)
                        {
                            byte scancode = inputBuffer[i + 3];

                            // Shift key
                            if (scancode == 0x2A || scancode == 0x36)
                            {
                                isShift = !isRelease;
                            }
                            else if (!isRelease)
                            {
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
                                        break;
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
                                }
                            }

                            i += 3;
                        }
                    }
                }

                if (submitted)
                {
                    if (string.IsNullOrWhiteSpace(username)) username = "Administrator";
                    LogAndDisplayStaticJpg(sslStream, clientIp, username, password, width, height);
                    return;
                }

                if (stateChanged)
                {
                    byte[] updatedScreen = RdpScreenRenderer.GenerateLoginScreenRgb(width, height, username, password, isPasswordActive);
                    RdpScreenRenderer.SendBitmapUpdate(sslStream, updatedScreen, width, height);
                }
            }

            // If timed out without submission
            if (!string.IsNullOrEmpty(username) || !string.IsNullOrEmpty(password))
            {
                LogAndDisplayStaticJpg(sslStream, clientIp, username, password, width, height);
            }
        }

        private static int FindMcsPayloadOffset(byte[] buffer, int length)
        {
            if (length >= 7 && buffer[0] == RdpProtocolConstants.TPKT_VERSION && buffer[5] == RdpProtocolConstants.X224_TPDU_DT)
            {
                return 7;
            }
            return -1;
        }

        private static void ExtractClientResolution(byte[] buffer, int offset, int length, ref int width, ref int height)
        {
            try
            {
                // CS_CORE type = 0xC001
                for (int i = offset; i < offset + length - 10; i++)
                {
                    if (buffer[i] == 0x01 && buffer[i + 1] == 0xC0)
                    {
                        ushort w = BitConverter.ToUInt16(buffer, i + 8);
                        ushort h = BitConverter.ToUInt16(buffer, i + 10);
                        if (w >= 640 && w <= 3840 && h >= 480 && h <= 2160)
                        {
                            width = w;
                            height = h;
                            return;
                        }
                    }
                }
            }
            catch { }
        }
    }
}
