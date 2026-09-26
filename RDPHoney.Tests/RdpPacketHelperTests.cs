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
        public void BuildMcsConnectResponse_GeneratesValidBerPacket()
        {
            byte[] packet = RdpPacketHelper.BuildMcsConnectResponse();

            Assert.True(packet.Length > 20);
            Assert.Equal(0x03, packet[0]); // TPKT Version
            Assert.Equal(RdpProtocolConstants.X224_TPDU_DT, packet[5]); // Data TPDU
            Assert.Equal(0x7F, packet[7]); // Application 102
            Assert.Equal(0x66, packet[8]);
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
            // Build mock TS_INFO_PACKET
            // CodePage (2), flags (4), cbDomain (2), cbUserName (2), cbPassword (2), cbAltShell (2), cbWorkDir (2)
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
