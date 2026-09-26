using System;
using System.IO;
using System.Text;

namespace RDPHoney
{
    // Purpose: Builds and parses RDP packets (TPKT, X.224, MCS, Licensing, Capabilities, Input).
    //
    // Dmitry Porotnikov

    public static class RdpPacketHelper
    {
        public static byte[] WrapTpktX224Data(byte[] payload)
        {
            int totalLength = 4 + 3 + payload.Length;
            byte[] packet = new byte[totalLength];

            // TPKT Header
            packet[0] = RdpProtocolConstants.TPKT_VERSION;
            packet[1] = 0x00;
            packet[2] = (byte)((totalLength >> 8) & 0xFF);
            packet[3] = (byte)(totalLength & 0xFF);

            // X.224 Data TPDU
            packet[4] = 0x02; // Length
            packet[5] = RdpProtocolConstants.X224_TPDU_DT; // 0xF0 Data
            packet[6] = 0x80; // EOT

            Buffer.BlockCopy(payload, 0, packet, 7, payload.Length);
            return packet;
        }

        public static byte[] BuildX224ConnectionConfirm(ushort destRef, uint selectedProtocol)
        {
            // TPKT Header (4) + X.224 CC (7) + RDP_NEG_RSP (8) = 19 bytes
            byte[] packet = new byte[19];

            // TPKT
            packet[0] = RdpProtocolConstants.TPKT_VERSION;
            packet[1] = 0x00;
            packet[2] = 0x00;
            packet[3] = 19;

            // X.224 CC
            packet[4] = 0x06; // Length
            packet[5] = RdpProtocolConstants.X224_TPDU_CC; // 0xD0
            packet[6] = (byte)(destRef & 0xFF);
            packet[7] = (byte)((destRef >> 8) & 0xFF);
            packet[8] = 0x00; // Source ref
            packet[9] = 0x00;
            packet[10] = 0x00; // Class 0

            // RDP Negotiation Response
            packet[11] = RdpProtocolConstants.RDP_NEG_RSP; // 0x02
            packet[12] = 0x00; // Flags
            packet[13] = 0x08; // Length (8)
            packet[14] = 0x00;
            packet[15] = (byte)(selectedProtocol & 0xFF);
            packet[16] = (byte)((selectedProtocol >> 8) & 0xFF);
            packet[17] = (byte)((selectedProtocol >> 16) & 0xFF);
            packet[18] = (byte)((selectedProtocol >> 24) & 0xFF);

            return packet;
        }

        public static byte[] BuildMcsConnectResponse()
        {
            // Standard GCC Conference Create Response
            byte[] gccResponse = new byte[] {
                0x00, 0x05, 0x00, 0x14, 0x7C, 0x00, 0x01, // Connect-GCC-PDU
                // SC_CORE (Server Core Data, length 12)
                0x0C, 0x01, 0x0C, 0x00, 0x04, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00,
                // SC_NET (Server Network Data, length 8)
                0x0C, 0x03, 0x08, 0x00, 0xEB, 0x03, 0x00, 0x00,
                // SC_SECURITY (Server Security Data, length 12)
                0x0C, 0x02, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            };

            using var ms = new MemoryStream();
            // BER Choice [APPLICATION 102]
            ms.WriteByte(0x7F);
            ms.WriteByte(0x66);

            // Calculate length of inner BER
            int innerLength = 3 + 3 + 26 + (2 + gccResponse.Length);
            WriteBerLength(ms, innerLength);

            // Result rt-successful (0)
            ms.Write(new byte[] { 0x0A, 0x01, 0x00 }, 0, 3);
            // calledConnectId
            ms.Write(new byte[] { 0x02, 0x01, 0x00 }, 0, 3);

            // domainParameters (26 bytes)
            ms.Write(new byte[] {
                0x30, 0x18,
                0x02, 0x01, 0x22, // maxChannelIds: 34
                0x02, 0x01, 0x02, // maxUserIds: 2
                0x02, 0x01, 0x00, // maxTokenIds: 0
                0x02, 0x01, 0x01, // numPriorities: 1
                0x02, 0x01, 0x00, // minThroughput: 0
                0x02, 0x01, 0x01, // maxHeight: 1
                0x02, 0x03, 0x00, 0xFF, 0xFF, // maxMCSPDUsize: 65535
                0x02, 0x01, 0x02  // protocolVersion: 2
            }, 0, 26);

            // UserData (OCTET STRING)
            ms.WriteByte(0x04);
            WriteBerLength(ms, gccResponse.Length);
            ms.Write(gccResponse, 0, gccResponse.Length);

            return WrapTpktX224Data(ms.ToArray());
        }

        public static byte[] BuildMcsAttachUserConfirm(ushort userId = 1002)
        {
            byte[] mcsPayload = new byte[] {
                RdpProtocolConstants.MCS_ATTACH_USER_CONFIRM, // 0x2E
                0x00, // result = rt-successful
                (byte)((userId >> 8) & 0xFF),
                (byte)(userId & 0xFF)
            };
            return WrapTpktX224Data(mcsPayload);
        }

        public static byte[] BuildMcsChannelJoinConfirm(ushort initiator, ushort channelId)
        {
            byte[] mcsPayload = new byte[] {
                RdpProtocolConstants.MCS_CHANNEL_JOIN_CONFIRM, // 0x3E
                0x00, // result = rt-successful
                (byte)((initiator >> 8) & 0xFF),
                (byte)(initiator & 0xFF),
                (byte)((channelId >> 8) & 0xFF),
                (byte)(channelId & 0xFF),
                (byte)((channelId >> 8) & 0xFF),
                (byte)(channelId & 0xFF)
            };
            return WrapTpktX224Data(mcsPayload);
        }

        public static byte[] BuildServerLicenseValidClientPDU()
        {
            using var ms = new MemoryStream();
            // MCS SendDataIndication header
            ms.Write(new byte[] {
                RdpProtocolConstants.MCS_SEND_DATA_INDICATION, // 0x68
                0x00, 0x01, // Initiator 1002
                0x03, 0xEB, // Channel 1003 (I/O)
                0x70 // Priority / flags
            }, 0, 6);

            // Security Header: SEC_LICENSE_PKT (0x0080)
            ms.Write(new byte[] { 0x80, 0x00, 0x00, 0x00 }, 0, 4);

            // License Error PDU: STATUS_VALID_CLIENT (0x00000007)
            ms.WriteByte(0xFF); // LICENSE_ERR_MSG
            ms.WriteByte(0x03); // LICENSE_VERSION_3_0
            ms.Write(new byte[] { 0x14, 0x00 }, 0, 2); // wMsgSize = 20
            ms.Write(new byte[] { 0x07, 0x00, 0x00, 0x00 }, 0, 4); // dwErrorCode = STATUS_VALID_CLIENT
            ms.Write(new byte[] { 0x02, 0x00, 0x00, 0x00 }, 0, 4); // dwStateTransition = ST_NO_TRANSITION
            ms.Write(new byte[] { 0x00, 0x00, 0x00, 0x00 }, 0, 4); // bbErrorInfo

            return WrapTpktX224Data(ms.ToArray());
        }

        public static byte[] BuildDemandActivePDU(int width, int height)
        {
            using var capMs = new MemoryStream();

            // 1. General Capability Set (24 bytes)
            capMs.Write(new byte[] {
                0x01, 0x00, 0x18, 0x00, // type=1, len=24
                0x01, 0x00, // OS Major = Windows
                0x04, 0x00, // OS Minor = Windows Server
                0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            }, 0, 24);

            // 2. Bitmap Capability Set (28 bytes)
            capMs.Write(new byte[] {
                0x02, 0x00, 0x1C, 0x00, // type=2, len=28
                0x18, 0x00, // prefBitsPerPixel = 24
                0x01, 0x00, // receive1BitPerPixel = true
                0x01, 0x00, // receive4BitsPerPixel = true
                0x01, 0x00, // receive8BitsPerPixel = true
                (byte)(width & 0xFF), (byte)((width >> 8) & 0xFF), // desktopWidth
                (byte)(height & 0xFF), (byte)((height >> 8) & 0xFF), // desktopHeight
                0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00
            }, 0, 28);

            // 3. Order Capability Set (88 bytes)
            byte[] orderCap = new byte[88];
            orderCap[0] = 0x03; orderCap[1] = 0x00; orderCap[2] = 88; orderCap[3] = 0x00; // type=3, len=88
            capMs.Write(orderCap, 0, orderCap.Length);

            // 4. Pointer Capability Set (10 bytes)
            capMs.Write(new byte[] {
                0x08, 0x00, 0x0A, 0x00, // type=8, len=10
                0x01, 0x00, 0x14, 0x00, 0x14, 0x00
            }, 0, 10);

            // 5. Input Capability Set (88 bytes)
            byte[] inputCap = new byte[88];
            inputCap[0] = 0x0D; inputCap[1] = 0x00; inputCap[2] = 88; inputCap[3] = 0x00; // type=13, len=88
            inputCap[4] = 0x35; inputCap[5] = 0x00; // inputFlags: SCANCODES | FASTPATH
            capMs.Write(inputCap, 0, inputCap.Length);

            byte[] capsData = capMs.ToArray();

            using var pduMs = new MemoryStream();
            // MCS SendDataIndication Header
            pduMs.Write(new byte[] {
                RdpProtocolConstants.MCS_SEND_DATA_INDICATION,
                0x00, 0x01, 0x03, 0xEB, 0x70
            }, 0, 6);

            // Share Control Header
            ushort shareLen = (ushort)(18 + 4 + capsData.Length);
            pduMs.WriteByte((byte)(shareLen & 0xFF));
            pduMs.WriteByte((byte)((shareLen >> 8) & 0xFF));
            pduMs.WriteByte(0x11); // TS_PDUTYPE_DEMANDACTIVEPDU
            pduMs.WriteByte(0x00);
            pduMs.Write(new byte[] { 0xEB, 0x03 }, 0, 2); // pduSource = 1003

            // Demand Active PDU data
            pduMs.Write(new byte[] { 0xEA, 0x03, 0x01, 0x00 }, 0, 4); // shareId = 0x000103EA
            pduMs.Write(new byte[] { 0x04, 0x00 }, 0, 2); // lengthSourceDescriptor = 4
            pduMs.Write(new byte[] { (byte)(capsData.Length & 0xFF), (byte)((capsData.Length >> 8) & 0xFF) }, 0, 2);
            pduMs.Write(Encoding.ASCII.GetBytes("RDP\0"), 0, 4); // sourceDescriptor
            pduMs.Write(new byte[] { 0x05, 0x00, 0x00, 0x00 }, 0, 4); // numberCapabilities = 5, pad
            pduMs.Write(capsData, 0, capsData.Length);

            return WrapTpktX224Data(pduMs.ToArray());
        }

        public static byte[] BuildSynchronizePDU()
        {
            using var ms = new MemoryStream();
            ms.Write(new byte[] { RdpProtocolConstants.MCS_SEND_DATA_INDICATION, 0x00, 0x01, 0x03, 0xEB, 0x70 }, 0, 6);
            // Share Data Header
            ms.Write(new byte[] {
                0x16, 0x00, // totalLength = 22
                0x17, 0x00, // TS_PDUTYPE_DATAPDU
                0xEB, 0x03, // pduSource = 1003
                0xEA, 0x03, 0x01, 0x00, // shareId
                0x00, 0x01, // pad, streamId
                0x06, 0x00, // uncompressedLength = 6
                0x1F, // pduType2 = SYNCHRONIZE
                0x00, // generalCompressedType
                0x00, 0x00, // generalCompressedLength
                0x01, 0x00, // messageType = 1
                0xEA, 0x03  // targetUser = 1002
            }, 0, 22);
            return WrapTpktX224Data(ms.ToArray());
        }

        public static byte[] BuildControlPDU(ushort action, ushort grantId = 0, uint controlId = 0)
        {
            using var ms = new MemoryStream();
            ms.Write(new byte[] { RdpProtocolConstants.MCS_SEND_DATA_INDICATION, 0x00, 0x01, 0x03, 0xEB, 0x70 }, 0, 6);
            // Share Data Header
            ms.Write(new byte[] {
                0x1C, 0x00, // totalLength = 28
                0x17, 0x00, // TS_PDUTYPE_DATAPDU
                0xEB, 0x03, // pduSource = 1003
                0xEA, 0x03, 0x01, 0x00, // shareId
                0x00, 0x01, // pad, streamId
                0x0C, 0x00, // uncompressedLength = 12
                0x14, // pduType2 = CONTROL
                0x00, // generalCompressedType
                0x00, 0x00, // generalCompressedLength
                (byte)(action & 0xFF), (byte)((action >> 8) & 0xFF),
                (byte)(grantId & 0xFF), (byte)((grantId >> 8) & 0xFF),
                (byte)(controlId & 0xFF), (byte)((controlId >> 8) & 0xFF),
                (byte)((controlId >> 16) & 0xFF), (byte)((controlId >> 24) & 0xFF)
            }, 0, 28);
            return WrapTpktX224Data(ms.ToArray());
        }

        public static byte[] BuildFontMapPDU()
        {
            using var ms = new MemoryStream();
            ms.Write(new byte[] { RdpProtocolConstants.MCS_SEND_DATA_INDICATION, 0x00, 0x01, 0x03, 0xEB, 0x70 }, 0, 6);
            ms.Write(new byte[] {
                0x18, 0x00, // totalLength = 24
                0x17, 0x00, // TS_PDUTYPE_DATAPDU
                0xEB, 0x03, // pduSource = 1003
                0xEA, 0x03, 0x01, 0x00, // shareId
                0x00, 0x01, // pad, streamId
                0x08, 0x00, // uncompressedLength = 8
                0x28, // pduType2 = FONTMAP
                0x00, // generalCompressedType
                0x00, 0x00, // generalCompressedLength
                0x00, 0x00, // numberEntries = 0
                0x00, 0x00, // totalNumEntries = 0
                0x03, 0x00  // mapFlags = 3 (FIRST | LAST)
            }, 0, 24);
            return WrapTpktX224Data(ms.ToArray());
        }

        private static void WriteBerLength(Stream stream, int length)
        {
            if (length < 128)
            {
                stream.WriteByte((byte)length);
            }
            else if (length <= 0xFF)
            {
                stream.WriteByte(0x81);
                stream.WriteByte((byte)length);
            }
            else
            {
                stream.WriteByte(0x82);
                stream.WriteByte((byte)((length >> 8) & 0xFF));
                stream.WriteByte((byte)(length & 0xFF));
            }
        }

        public static (string username, string password, string domain) ExtractCredentialsFromInfoPacket(byte[] data, int offset, int length)
        {
            try
            {
                // Search for TS_INFO_PACKET inside packet
                // TS_INFO_PACKET structure:
                // CodePage (2), flags (4), cbDomain (2), cbUserName (2), cbPassword (2), cbAlternateShell (2), cbWorkingDir (2) = 16 bytes header
                for (int i = offset; i <= offset + length - 16; i++)
                {
                    uint flags = BitConverter.ToUInt32(data, i + 2);
                    ushort cbDomain = BitConverter.ToUInt16(data, i + 6);
                    ushort cbUserName = BitConverter.ToUInt16(data, i + 8);
                    ushort cbPassword = BitConverter.ToUInt16(data, i + 10);

                    // Sanity check lengths
                    if (cbDomain <= 256 && cbUserName > 0 && cbUserName <= 256 && cbPassword <= 512)
                    {
                        int payloadStart = i + 16;
                        if (payloadStart + cbDomain + cbUserName + cbPassword <= offset + length)
                        {
                            bool isUnicode = (flags & RdpProtocolConstants.INFO_UNICODE) != 0;
                            var enc = isUnicode ? Encoding.Unicode : Encoding.ASCII;

                            string domain = cbDomain > 0 ? enc.GetString(data, payloadStart, cbDomain).TrimEnd('\0') : "";
                            string username = enc.GetString(data, payloadStart + cbDomain, cbUserName).TrimEnd('\0');

                            string password = "";
                            if (cbPassword > 0)
                            {
                                int passOffset = payloadStart + cbDomain + cbUserName;
                                if ((flags & RdpProtocolConstants.INFO_PASSWORD_IS_SCRAMBLED) != 0)
                                {
                                    // Descramble 512-byte scrambled password (first 2 bytes = length)
                                    ushort actualLen = BitConverter.ToUInt16(data, passOffset);
                                    if (actualLen > 0 && actualLen <= 510)
                                    {
                                        byte[] descrambled = new byte[actualLen];
                                        for (int b = 0; b < actualLen; b++)
                                        {
                                            descrambled[b] = (byte)(data[passOffset + 2 + b] ^ 0xA5);
                                        }
                                        password = enc.GetString(descrambled).TrimEnd('\0');
                                    }
                                }
                                else
                                {
                                    password = enc.GetString(data, passOffset, cbPassword).TrimEnd('\0');
                                }
                            }

                            if (!string.IsNullOrEmpty(username) && !username.Contains('\0'))
                            {
                                return (username, password, domain);
                            }
                        }
                    }
                }
            }
            catch
            {
                // Parsing fallback
            }

            return ("", "", "");
        }

        public static char ScancodeToChar(byte scancode, bool isShift)
        {
            return scancode switch
            {
                0x02 => isShift ? '!' : '1',
                0x03 => isShift ? '@' : '2',
                0x04 => isShift ? '#' : '3',
                0x05 => isShift ? '$' : '4',
                0x06 => isShift ? '%' : '5',
                0x07 => isShift ? '^' : '6',
                0x08 => isShift ? '&' : '7',
                0x09 => isShift ? '*' : '8',
                0x0A => isShift ? '(' : '9',
                0x0B => isShift ? ')' : '0',
                0x0C => isShift ? '_' : '-',
                0x0D => isShift ? '+' : '=',
                0x10 => isShift ? 'Q' : 'q',
                0x11 => isShift ? 'W' : 'w',
                0x12 => isShift ? 'E' : 'e',
                0x13 => isShift ? 'R' : 'r',
                0x14 => isShift ? 'T' : 't',
                0x15 => isShift ? 'Y' : 'y',
                0x16 => isShift ? 'U' : 'u',
                0x17 => isShift ? 'I' : 'i',
                0x18 => isShift ? 'O' : 'o',
                0x19 => isShift ? 'P' : 'p',
                0x1E => isShift ? 'A' : 'a',
                0x1F => isShift ? 'S' : 's',
                0x20 => isShift ? 'D' : 'd',
                0x21 => isShift ? 'F' : 'f',
                0x22 => isShift ? 'G' : 'g',
                0x23 => isShift ? 'H' : 'h',
                0x24 => isShift ? 'J' : 'j',
                0x25 => isShift ? 'K' : 'k',
                0x26 => isShift ? 'L' : 'l',
                0x2C => isShift ? 'Z' : 'z',
                0x2D => isShift ? 'X' : 'x',
                0x2E => isShift ? 'C' : 'c',
                0x2F => isShift ? 'V' : 'v',
                0x30 => isShift ? 'B' : 'b',
                0x31 => isShift ? 'N' : 'n',
                0x32 => isShift ? 'M' : 'm',
                0x39 => ' ',
                0x33 => isShift ? '<' : ',',
                0x34 => isShift ? '>' : '.',
                0x35 => isShift ? '?' : '/',
                _ => '\0'
            };
        }
    }
}
