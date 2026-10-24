using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using RDPHoney;
using Xunit;

namespace RDPHoney.Tests
{
    [Collection("DatabaseTests")]
    public class EnhancedRDPServerHoneypotTests
    {
        private static int GetAvailablePort()
        {
            using var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            int port = ((IPEndPoint)listener.LocalEndpoint).Port;
            listener.Stop();
            return port;
        }

        [Fact]
        public void ResolvePort_DefaultsTo3389()
        {
            Environment.SetEnvironmentVariable("HONEYPOT_PORT", null);
            Environment.SetEnvironmentVariable("RDP_PORT", null);

            int port = EnhancedRDPServerHoneypot.ResolvePort();
            Assert.Equal(3389, port);
        }

        [Fact]
        public void ResolvePort_ReadsFromEnvironmentVariable()
        {
            try
            {
                Environment.SetEnvironmentVariable("HONEYPOT_PORT", "43389");
                int port = EnhancedRDPServerHoneypot.ResolvePort();
                Assert.Equal(43389, port);
            }
            finally
            {
                Environment.SetEnvironmentVariable("HONEYPOT_PORT", null);
            }
        }

        [Fact]
        public async Task HoneypotServer_StartsAndStopsCleanly()
        {
            int testPort = GetAvailablePort();
            var server = new EnhancedRDPServerHoneypot(testPort);

            var serverTask = Task.Run(() => server.Start());

            // Give it time to bind and listen
            await Task.Delay(300);
            Assert.True(server.IsRunning);

            // Connect a client to verify it accepts connections
            using (var client = new TcpClient())
            {
                await client.ConnectAsync("127.0.0.1", testPort);
                Assert.True(client.Connected);
            }

            // Stop server
            server.Stop();
            await Task.WhenAny(serverTask, Task.Delay(2000));
            Assert.False(server.IsRunning);
        }

        [Fact]
        public async Task FullRdpHandshake_InteractiveLogin_RendersLoginAndStaticJpg()
        {
            string tempDb = Path.Combine(Path.GetTempPath(), $"rdp_e2e_{Guid.NewGuid():N}.db");
            DatabaseLogger.DatabasePath = tempDb;
            DatabaseLogger.InitializeDatabase();

            int testPort = GetAvailablePort();
            var server = new EnhancedRDPServerHoneypot(testPort);
            var serverTask = Task.Run(() => server.Start());
            await Task.Delay(200);

            try
            {
                using var client = new TcpClient();
                await client.ConnectAsync("127.0.0.1", testPort);
                var rawStream = client.GetStream();

                // 1. Send X.224 Connection Request with RDP_NEG_REQ (PROTOCOL_SSL | PROTOCOL_HYBRID = 3)
                byte[] x224Cr = new byte[] {
                    0x03, 0x00, 0x00, 0x13, // TPKT (19)
                    0x0E, 0xE0, 0x00, 0x00, 0x34, 0x12, 0x00, // X.224 CR
                    0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00 // RDP_NEG_REQ (SSL | HYBRID)
                };
                await rawStream.WriteAsync(x224Cr);

                // Read X.224 Connection Confirm
                byte[]? cc = RdpPacketHelper.ReadNextPdu(rawStream);
                Assert.NotNull(cc);
                Assert.Equal(19, cc.Length);
                Assert.Equal(0x0E, cc[4]);
                Assert.Equal(RdpProtocolConstants.X224_TPDU_CC, cc[5]);

                // 2. Establish TLS
                using var sslStream = new System.Net.Security.SslStream(rawStream, false, (_, _, _, _) => true);
                await sslStream.AuthenticateAsClientAsync("WIN-SRV-2019");

                // 3. Send MCS Connect Initial with CS_CORE (800x600, 24bpp) and CS_NET (1 channel)
                using var mcsInitMs = new MemoryStream();
                mcsInitMs.Write(new byte[] { 0x7F, 0x65, 0x20 }, 0, 3);
                // CS_CORE (type = 0xC001, len = 16, version = 0x00080004, w = 800, h = 600, depth = 0xCA04)
                mcsInitMs.Write(new byte[] {
                    0x01, 0xC0, 0x10, 0x00,
                    0x04, 0x00, 0x08, 0x00,
                    0x20, 0x03, // 800
                    0x58, 0x02, // 600
                    0x04, 0xCA, 0x01, 0xAA
                }, 0, 16);
                // CS_NET (type = 0xC003, len = 20, channelCount = 1, 12-byte channel def)
                mcsInitMs.Write(new byte[] {
                    0x03, 0xC0, 0x14, 0x00,
                    0x01, 0x00, 0x00, 0x00,
                    (byte)'c', (byte)'l', (byte)'i', (byte)'p', (byte)'r', (byte)'d', (byte)'r', 0,
                    0x00, 0x00, 0x00, 0x00
                }, 0, 20);
                byte[] mcsInitPdu = RdpPacketHelper.WrapTpktX224Data(mcsInitMs.ToArray());
                await sslStream.WriteAsync(mcsInitPdu);

                // Read MCS Connect Response
                byte[]? mcsResp = RdpPacketHelper.ReadNextPdu(sslStream);
                Assert.NotNull(mcsResp);
                Assert.Equal(0x7F, mcsResp[7]);
                Assert.Equal(0x66, mcsResp[8]);

                // 4. Send MCS Erect Domain Request (0x04) + MCS Attach User Request (0x28)
                byte[] erectDomain = RdpPacketHelper.WrapTpktX224Data(new byte[] { 0x04, 0x01, 0x00, 0x01, 0x00 });
                byte[] attachUser = RdpPacketHelper.WrapTpktX224Data(new byte[] { 0x28 });
                await sslStream.WriteAsync(erectDomain);
                await sslStream.WriteAsync(attachUser);

                // Read MCS Attach User Confirm
                byte[]? attachConf = RdpPacketHelper.ReadNextPdu(sslStream);
                Assert.NotNull(attachConf);
                Assert.Equal(0x2E, attachConf[7]);
                ushort assignedUserId = (ushort)(((attachConf[9] << 8) | attachConf[10]) + 1001);
                Assert.Equal(1005, assignedUserId);

                // 5. Join channels (userChannel=1005, IO=1003, cliprdr=1004)
                foreach (ushort ch in new ushort[] { assignedUserId, 1003, 1004 })
                {
                    ushort initOff = (ushort)(assignedUserId - 1001);
                    byte[] joinReq = RdpPacketHelper.WrapTpktX224Data(new byte[] {
                        0x38,
                        (byte)(initOff >> 8), (byte)(initOff & 0xFF),
                        (byte)(ch >> 8), (byte)(ch & 0xFF)
                    });
                    await sslStream.WriteAsync(joinReq);

                    byte[]? joinConf = RdpPacketHelper.ReadNextPdu(sslStream);
                    Assert.NotNull(joinConf);
                    Assert.Equal(0x3E, joinConf[7]);
                }

                // 6. Send Client Info PDU with username="alice" and empty password (interactive login)
                using var infoMs = new MemoryStream();
                infoMs.Write(new byte[] { 0x40, 0x00, 0x00, 0x00 }, 0, 4); // SEC_INFO_PKT
                infoMs.Write(new byte[] { 0x00, 0x00, 0x00, 0x00 }, 0, 4); // CodePage
                infoMs.Write(BitConverter.GetBytes(RdpProtocolConstants.INFO_UNICODE), 0, 4); // flags
                byte[] userBytes = System.Text.Encoding.Unicode.GetBytes("alice");
                infoMs.Write(BitConverter.GetBytes((ushort)0), 0, 2); // cbDomain
                infoMs.Write(BitConverter.GetBytes((ushort)userBytes.Length), 0, 2); // cbUserName
                infoMs.Write(BitConverter.GetBytes((ushort)0), 0, 2); // cbPassword = 0 (interactive)
                infoMs.Write(new byte[] { 0x00, 0x00, 0x00, 0x00 }, 0, 4); // cbAltShell, cbWorkDir
                infoMs.Write(new byte[] { 0x00, 0x00 }, 0, 2); // Domain null term
                infoMs.Write(userBytes, 0, userBytes.Length);
                infoMs.Write(new byte[] { 0x00, 0x00 }, 0, 2); // UserName null term
                infoMs.Write(new byte[] { 0x00, 0x00 }, 0, 2); // Password null term
                byte[] clientInfoPdu = RdpPacketHelper.WrapSendDataIndication(infoMs.ToArray(), assignedUserId, 1003);
                clientInfoPdu[7] = RdpProtocolConstants.MCS_SEND_DATA_REQUEST; // 0x64
                await sslStream.WriteAsync(clientInfoPdu);

                // 7. Read License Valid Client PDU and Demand Active PDU
                byte[]? licPdu = RdpPacketHelper.ReadNextPdu(sslStream);
                Assert.NotNull(licPdu);
                Assert.Equal(0x80, licPdu[15]); // SEC_LICENSE_PKT

                byte[]? demandActive = RdpPacketHelper.ReadNextPdu(sslStream);
                Assert.NotNull(demandActive);
                Assert.Equal(0x11, demandActive[17]); // TS_PDUTYPE_DEMANDACTIVEPDU

                // 8. Send Client Confirm Active PDU + Client Font List PDU
                byte[] confirmActivePayload = new byte[] {
                    0x16, 0x00, 0x13, 0x00, 0xED, 0x03, // ShareControlHeader (TS_PDUTYPE_CONFIRMACTIVEPDU = 0x0013)
                    0xEA, 0x03, 0x01, 0x00, 0xEA, 0x03, 0x04, 0x00, 0x04, 0x00,
                    (byte)'M', (byte)'S', (byte)'T', 0,
                    0x00, 0x00, 0x00, 0x00
                };
                byte[] confirmActive = RdpPacketHelper.WrapSendDataIndication(confirmActivePayload, assignedUserId, 1003);
                confirmActive[7] = RdpProtocolConstants.MCS_SEND_DATA_REQUEST;
                await sslStream.WriteAsync(confirmActive);

                byte[] fontListPayload = new byte[] {
                    0x1A, 0x00, 0x17, 0x00, 0xED, 0x03, // TS_PDUTYPE_DATAPDU
                    0xEA, 0x03, 0x01, 0x00, 0x00, 0x01, 0x08, 0x00, 0x27, 0x00, 0x00, 0x00, // TS_PDUTYPE2_FONT_LIST (0x27)
                    0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x32, 0x00
                };
                byte[] fontList = RdpPacketHelper.WrapSendDataIndication(fontListPayload, assignedUserId, 1003);
                fontList[7] = RdpProtocolConstants.MCS_SEND_DATA_REQUEST;
                await sslStream.WriteAsync(fontList);

                // 9. Read Server Finalization PDUs (Synchronize, Control Cooperate, Control Granted, Font Map, System Pointer) + initial Login Screen Fast-Path Bitmap PDUs
                // 800x600 @ 24bpp: 14000 / 2400 = 5 rows/strip => 120 strips for full screen
                int fastPathBitmapCount = 0;
                while (fastPathBitmapCount < 120)
                {
                    byte[]? pdu = RdpPacketHelper.ReadNextPdu(sslStream);
                    Assert.NotNull(pdu);
                    if (pdu[0] == 0x00 && pdu[3] == 0x01) // Fast-Path Bitmap Update
                    {
                        fastPathBitmapCount++;
                    }
                }
                Assert.Equal(120, fastPathBitmapCount);

                // 10. Send Fast-Path Keyboard Scancodes: '1' (0x02), '2' (0x03), '3' (0x04), Enter (0x1C) in a single 4-event Fast-Path Input PDU
                byte[] fpKeyPresses = new byte[] {
                    (byte)(4 << 2), // action=0, numEvents=4
                    10,             // total length = 10
                    0x00, 0x02,     // '1'
                    0x00, 0x03,     // '2'
                    0x00, 0x04,     // '3'
                    0x00, 0x1C      // Enter
                };
                await sslStream.WriteAsync(fpKeyPresses);

                // 11. Read Static Desktop JPG Fast-Path Bitmap Updates sent after login submission
                int desktopBitmapCount = 0;
                while (desktopBitmapCount < 10)
                {
                    byte[]? pdu = RdpPacketHelper.ReadNextPdu(sslStream);
                    Assert.NotNull(pdu);
                    if (pdu[0] == 0x00 && pdu[3] == 0x01)
                    {
                        desktopBitmapCount++;
                    }
                }
                Assert.True(desktopBitmapCount >= 10);
                Assert.True(DatabaseLogger.CheckIfRdpClientExists("127.0.0.1"));
            }
            finally
            {
                server.Stop();
                await Task.WhenAny(serverTask, Task.Delay(2000));
                try
                {
                    Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
                    if (File.Exists(tempDb)) File.Delete(tempDb);
                }
                catch { }
            }
        }
    }
}
