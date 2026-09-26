using System;
using System.Text;
using RDPHoney;
using Xunit;

namespace RDPHoney.Tests
{
    public class RdpPacketHelperTests
    {
        [Fact]
        public void BuildX224ConnectionConfirm_GeneratesValidTpktAndNegRsp()
        {
            byte[] packet = RdpPacketHelper.BuildX224ConnectionConfirm(0x1234, RdpProtocolConstants.PROTOCOL_SSL);

            Assert.Equal(19, packet.Length);
            Assert.Equal(0x03, packet[0]); // TPKT Version
            Assert.Equal(19, packet[3]); // Total length
            Assert.Equal(RdpProtocolConstants.X224_TPDU_CC, packet[5]); // Connection Confirm (0xD0)
            Assert.Equal(RdpProtocolConstants.RDP_NEG_RSP, packet[11]); // RDP_NEG_RSP (0x02)
            Assert.Equal(0x01, packet[15]); // PROTOCOL_SSL
        }

        [Fact]
        public void BuildMcsConnectResponse_GeneratesValidBerPacketWithGcc()
        {
            byte[] packet = RdpPacketHelper.BuildMcsConnectResponse();

            Assert.True(packet.Length > 50);
            Assert.Equal(0x03, packet[0]); // TPKT Version
            Assert.Equal(RdpProtocolConstants.X224_TPDU_DT, packet[5]); // Data TPDU (0xF0)
            Assert.Equal(0x7F, packet[7]); // Application 102
            Assert.Equal(0x66, packet[8]);

            // Verify "McDn" H.221 server-to-client key is present
            string packetStr = Encoding.ASCII.GetString(packet);
            Assert.Contains("McDn", packetStr);
        }

        [Fact]
        public void BuildMcsAttachUserConfirm_UsesCorrectPerIntegerOffset()
        {
            byte[] packet = RdpPacketHelper.BuildMcsAttachUserConfirm(1002);

            Assert.Equal(11, packet.Length);
            Assert.Equal(0x2E, packet[7]); // AttachUserConfirm
            Assert.Equal(0x00, packet[8]); // rt-successful
            Assert.Equal(0x00, packet[9]); // user offset hi (1002 - 1001 = 1)
            Assert.Equal(0x01, packet[10]); // user offset lo
        }

        [Fact]
        public void BuildMcsChannelJoinConfirm_UsesCorrectInitiatorAndChannel()
        {
            byte[] packet = RdpPacketHelper.BuildMcsChannelJoinConfirm(1002, 1003);

            Assert.Equal(15, packet.Length);
            Assert.Equal(0x3E, packet[7]); // ChannelJoinConfirm
            Assert.Equal(0x00, packet[8]); // rt-successful
            Assert.Equal(0x00, packet[9]); // initiator offset hi
            Assert.Equal(0x01, packet[10]); // initiator offset lo (1002 - 1001 = 1)
            Assert.Equal(0x03, packet[11]); // channel 1003 hi
            Assert.Equal(0xEB, packet[12]); // channel 1003 lo
        }

        [Fact]
        public void BuildServerLicenseValidClientPDU_GeneratesValidMcsSendDataIndication()
        {
            byte[] packet = RdpPacketHelper.BuildServerLicenseValidClientPDU();

            // Total: TPKT (4) + X.224 DT (3) + MCS SendDataIndication (8) + SecHeader (4) + LicMsg (16) = 35 bytes
            Assert.Equal(35, packet.Length);
            Assert.Equal(0x03, packet[0]); // TPKT Version
            Assert.Equal(35, packet[3]); // Total length
            Assert.Equal(0xF0, packet[5]); // X.224 Data
            Assert.Equal(0x68, packet[7]); // MCS SendDataIndication
            Assert.Equal(0x00, packet[8]); // Initiator offset hi
            Assert.Equal(0x01, packet[9]); // Initiator offset lo (1002 - 1001 = 1)
            Assert.Equal(0x03, packet[10]); // Channel 1003 hi
            Assert.Equal(0xEB, packet[11]); // Channel 1003 lo
            Assert.Equal(0x70, packet[12]); // dataPriority + segmentation
            Assert.Equal(0x80, packet[13]); // PER length hi (20 | 0x8000)
            Assert.Equal(0x14, packet[14]); // PER length lo (20 bytes)
            Assert.Equal(0x80, packet[15]); // SEC_LICENSE_PKT
        }

        [Fact]
        public void BuildDemandActivePDU_GeneratesValidMcsSendDataIndicationWithCaps()
        {
            byte[] packet = RdpPacketHelper.BuildDemandActivePDU(1024, 768);

            Assert.True(packet.Length > 100);
            Assert.Equal(0x03, packet[0]); // TPKT
            Assert.Equal(0xF0, packet[5]); // X.224 DT
            Assert.Equal(0x68, packet[7]); // MCS SendDataIndication
            Assert.Equal(0x00, packet[8]); // Initiator
            Assert.Equal(0x01, packet[9]);
            Assert.Equal(0x03, packet[10]); // Channel 1003
            Assert.Equal(0xEB, packet[11]);
            Assert.Equal(0x70, packet[12]); // Priority
            Assert.True((packet[13] & 0x80) != 0); // PER length bit set
        }

        [Fact]
        public void ShouldDropClient_ExemptsLoopbackAndHonorsEnvVar()
        {
            Assert.False(RdpConnectionHandler.ShouldDropClient("127.0.0.1"));
            Assert.False(RdpConnectionHandler.ShouldDropClient("::1"));

            try
            {
                Environment.SetEnvironmentVariable("AUTO_BAN_RDP_CLIENTS", "false");
                Assert.False(RdpConnectionHandler.ShouldDropClient("198.51.100.99"));
            }
            finally
            {
                Environment.SetEnvironmentVariable("AUTO_BAN_RDP_CLIENTS", null);
            }
        }

        [Fact]
        public void ScancodeToChar_MapsLettersAndDigits()
        {
            Assert.Equal('a', RdpPacketHelper.ScancodeToChar(0x1E, isShift: false));
            Assert.Equal('A', RdpPacketHelper.ScancodeToChar(0x1E, isShift: true));
            Assert.Equal('1', RdpPacketHelper.ScancodeToChar(0x02, isShift: false));
            Assert.Equal('!', RdpPacketHelper.ScancodeToChar(0x02, isShift: true));
            Assert.Equal(' ', RdpPacketHelper.ScancodeToChar(0x39, isShift: false));
        }

        [Fact]
        public void ExtractCredentialsFromInfoPacket_ExtractsUsernameAndPassword()
        {
            string domain = "WORKGROUP";
            string user = "Administrator";
            string pass = "H0neyP0t!";

            byte[] domainBytes = Encoding.Unicode.GetBytes(domain);
            byte[] userBytes = Encoding.Unicode.GetBytes(user);
            byte[] passBytes = Encoding.Unicode.GetBytes(pass);

            using var ms = new System.IO.MemoryStream();
            ms.Write(new byte[] { 0x00, 0x00 }, 0, 2); // CodePage
            ms.Write(BitConverter.GetBytes(RdpProtocolConstants.INFO_UNICODE), 0, 4); // flags
            ms.Write(BitConverter.GetBytes((ushort)domainBytes.Length), 0, 2);
            ms.Write(BitConverter.GetBytes((ushort)userBytes.Length), 0, 2);
            ms.Write(BitConverter.GetBytes((ushort)passBytes.Length), 0, 2);
            ms.Write(new byte[] { 0x00, 0x00, 0x00, 0x00 }, 0, 4); // cbAltShell, cbWorkDir
            ms.Write(domainBytes, 0, domainBytes.Length);
            ms.Write(userBytes, 0, userBytes.Length);
            ms.Write(passBytes, 0, passBytes.Length);

            byte[] pdu = ms.ToArray();
            var result = RdpPacketHelper.ExtractCredentialsFromInfoPacket(pdu, 0, pdu.Length);

            Assert.Equal(user, result.username);
            Assert.Equal(pass, result.password);
            Assert.Equal(domain, result.domain);
        }
    }
}
