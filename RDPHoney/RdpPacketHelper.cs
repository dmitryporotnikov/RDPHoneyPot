using System;
using System.IO;
using System.Text;

namespace RDPHoney
{
    // Purpose: Builds and parses RDP packets (TPKT, X.224, MCS, Licensing, Capabilities, Finalization, Input).
    //
    // Dmitry Porotnikov

    public static class RdpPacketHelper
    {
        public static byte[] WrapTpktX224Data(byte[] payload)
        {
            int totalLength = 4 + 3 + payload.Length;
            byte[] packet = new byte[totalLength];

            // TPKT Header (4 bytes)
            packet[0] = RdpProtocolConstants.TPKT_VERSION;
            packet[1] = 0x00;
            packet[2] = (byte)((totalLength >> 8) & 0xFF);
            packet[3] = (byte)(totalLength & 0xFF);

            // X.224 Data TPDU (3 bytes)
            packet[4] = 0x02; // Length
            packet[5] = RdpProtocolConstants.X224_TPDU_DT; // 0xF0 Data
            packet[6] = 0x80; // EOT

            Buffer.BlockCopy(payload, 0, packet, 7, payload.Length);
            return packet;
        }

        public static byte[] WrapSendDataIndication(byte[] userData, ushort userId = 1002, ushort channelId = 1003)
        {
            // MCS SendDataIndication header length:
            // 1 (choice 0x68) + 2 (initiator) + 2 (channelId) + 1 (dataPriority) + 2 (PER length) = 8 bytes
            int mcsHeaderLen = 8;
            int totalLength = 4 + 3 + mcsHeaderLen + userData.Length;
            byte[] packet = new byte[totalLength];

            // 1. TPKT Header (4 bytes)
            packet[0] = RdpProtocolConstants.TPKT_VERSION; // 0x03
            packet[1] = 0x00;
            packet[2] = (byte)((totalLength >> 8) & 0xFF);
            packet[3] = (byte)(totalLength & 0xFF);

            // 2. X.224 Data TPDU (3 bytes)
            packet[4] = 0x02; // Length
            packet[5] = RdpProtocolConstants.X224_TPDU_DT; // 0xF0
            packet[6] = 0x80; // EOT

            // 3. MCS SendDataIndication (8 bytes)
            // PER choice: DomainMCSPDU_SendDataIndication (26) << 2 = 0x68
            packet[7] = RdpProtocolConstants.MCS_SEND_DATA_INDICATION; // 0x68
            ushort initiatorOffset = (ushort)(userId - 1001);
            packet[8] = (byte)((initiatorOffset >> 8) & 0xFF); // 0x00
            packet[9] = (byte)(initiatorOffset & 0xFF);        // 0x01
            packet[10] = (byte)((channelId >> 8) & 0xFF);      // 0x03
            packet[11] = (byte)(channelId & 0xFF);             // 0xEB
            packet[12] = 0x70; // dataPriority (medium) | segmentation (begin | end)

            // PER length of userData (2 bytes big-endian: userData.Length | 0x8000)
            int perLen = userData.Length | 0x8000;
            packet[13] = (byte)((perLen >> 8) & 0xFF);
            packet[14] = (byte)(perLen & 0xFF);

            // 4. UserData
            Buffer.BlockCopy(userData, 0, packet, 15, userData.Length);

            return packet;
        }

        public static byte[]? ReadNextPdu(Stream stream)
        {
            int firstByte = stream.ReadByte();
            if (firstByte < 0)
            {
                return null;
            }

            if (firstByte == RdpProtocolConstants.TPKT_VERSION)
            {
                // Standard TPKT packet: 4-byte header (0x03, 0x00, lenHi, lenLo)
                byte[] header = new byte[4];
                header[0] = (byte)firstByte;
                if (!ReadExact(stream, header, 1, 3))
                {
                    return null;
                }

                int totalLen = (header[2] << 8) | header[3];
                if (totalLen < 4 || totalLen > 65535)
                {
                    return header;
                }

                byte[] packet = new byte[totalLen];
                Buffer.BlockCopy(header, 0, packet, 0, 4);
                if (!ReadExact(stream, packet, 4, totalLen - 4))
                {
                    return null;
                }

                return packet;
            }
            else
            {
                // Fast-Path Input PDU: byte 0 = fpInputHeader, byte 1 = length1, optional byte 2 = length2
                int len1 = stream.ReadByte();
                if (len1 < 0)
                {
                    return null;
                }

                int totalLen;
                int headerLen;
                byte len2Byte = 0;

                if ((len1 & 0x80) != 0)
                {
                    int len2 = stream.ReadByte();
                    if (len2 < 0)
                    {
                        return null;
                    }
                    len2Byte = (byte)len2;
                    totalLen = ((len1 & 0x7F) << 8) | len2;
                    headerLen = 3;
                }
                else
                {
                    totalLen = len1;
                    headerLen = 2;
                }

                if (totalLen < headerLen || totalLen > 65535)
                {
                    return new byte[] { (byte)firstByte, (byte)len1 };
                }

                byte[] packet = new byte[totalLen];
                packet[0] = (byte)firstByte;
                packet[1] = (byte)len1;
                if (headerLen == 3)
                {
                    packet[2] = len2Byte;
                }

                if (!ReadExact(stream, packet, headerLen, totalLen - headerLen))
                {
                    return null;
                }

                return packet;
            }
        }

        private static bool ReadExact(Stream stream, byte[] buffer, int offset, int count)
        {
            int totalRead = 0;
            while (totalRead < count)
            {
                int read = stream.Read(buffer, offset + totalRead, count - totalRead);
                if (read <= 0)
                {
                    return false;
                }
                totalRead += read;
            }
            return true;
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

            // X.224 CC (LI = 14 bytes: 6 bytes fixed CC header + 8 bytes RDP_NEG_RSP)
            packet[4] = 0x0E; // Length indicator (14)
            packet[5] = RdpProtocolConstants.X224_TPDU_CC; // 0xD0
            packet[6] = (byte)(destRef & 0xFF);
            packet[7] = (byte)((destRef >> 8) & 0xFF);
            packet[8] = 0x12; // Source ref (0x1234)
            packet[9] = 0x34;
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

        public static byte[] BuildMcsConnectResponse(uint clientRequestedProtocols = RdpProtocolConstants.PROTOCOL_SSL, int channelCount = 0)
        {
            if (channelCount < 0) channelCount = 0;
            if (channelCount > 31) channelCount = 31;

            // 1. Server Data Blocks (userData)
            using var serverDataMs = new MemoryStream();

            // SC_CORE (type = 0x0C01, length = 12)
            serverDataMs.Write(new byte[] {
                0x01, 0x0C, // type = SC_CORE (0x0C01, LE)
                0x0C, 0x00, // length = 12
                0x04, 0x00, 0x08, 0x00, // serverVersion = RDP 5.0-8.1+ (0x00080004)
                (byte)(clientRequestedProtocols & 0xFF),
                (byte)((clientRequestedProtocols >> 8) & 0xFF),
                (byte)((clientRequestedProtocols >> 16) & 0xFF),
                (byte)((clientRequestedProtocols >> 24) & 0xFF) // clientRequestedProtocols echoed from RDP_NEG_REQ
            }, 0, 12);

            // SC_NET (type = 0x0C03, length = 8 + channelCount * 2 + padding)
            int scNetPadding = (channelCount % 2 == 1) ? 2 : 0;
            ushort scNetLength = (ushort)(8 + channelCount * 2 + scNetPadding);
            serverDataMs.Write(new byte[] {
                0x03, 0x0C, // type = SC_NET (0x0C03, LE)
                (byte)(scNetLength & 0xFF), (byte)((scNetLength >> 8) & 0xFF),
                0xEB, 0x03, // MCSChannelId = 1003 (0x03EB, LE)
                (byte)(channelCount & 0xFF), (byte)((channelCount >> 8) & 0xFF)
            }, 0, 8);

            for (int i = 0; i < channelCount; i++)
            {
                ushort chId = (ushort)(1004 + i);
                serverDataMs.WriteByte((byte)(chId & 0xFF));
                serverDataMs.WriteByte((byte)((chId >> 8) & 0xFF));
            }
            if (scNetPadding > 0)
            {
                serverDataMs.Write(new byte[] { 0x00, 0x00 }, 0, 2);
            }

            // SC_SECURITY (type = 0x0C02, length = 12)
            serverDataMs.Write(new byte[] {
                0x02, 0x0C, // type = SC_SECURITY (0x0C02, LE)
                0x0C, 0x00, // length = 12
                0x00, 0x00, 0x00, 0x00, // encryptionMethod = 0 (None, TLS handles encryption)
                0x00, 0x00, 0x00, 0x00  // encryptionLevel = 0
            }, 0, 12);

            byte[] serverData = serverDataMs.ToArray();

            // 2. Inner ConnectGCCPDU (PER-encoded GCC ConferenceCreateResponse)
            using var innerGccMs = new MemoryStream();
            innerGccMs.WriteByte(0x14); // ConnectGCCPDU choice: conferenceCreateResponse (0x14)
            innerGccMs.Write(new byte[] { 0x76, 0x0A }, 0, 2); // nodeID: 0x79F3 (0x79F3 - 1001 = 30218 = 0x760A)
            innerGccMs.Write(new byte[] { 0x01, 0x01 }, 0, 2); // tag: 1 (0x01, 0x01)
            innerGccMs.WriteByte(0x00); // result: success (0)
            innerGccMs.WriteByte(0x01); // number of UserData sets: 1
            innerGccMs.WriteByte(0xC0); // UserData choice: value present + h221NonStandard (0xC0)
            // h221NonStandard key: "McDn" (length = 4, min = 4 -> mlength = 0)
            innerGccMs.WriteByte(0x00); // mlength = 0
            innerGccMs.Write(Encoding.ASCII.GetBytes("McDn"), 0, 4); // "McDn"
            // userData OCTET STRING (serverData)
            WritePerLength(innerGccMs, serverData.Length);
            innerGccMs.Write(serverData, 0, serverData.Length);

            byte[] innerGcc = innerGccMs.ToArray();

            using var gccMs = new MemoryStream();
            gccMs.WriteByte(0x00); // ConnectData choice: object (0)
            // OID: 0.0.20.124.0.1 (t124_02_98_oid)
            gccMs.Write(new byte[] { 0x05, 0x00, 0x14, 0x7C, 0x00, 0x01 }, 0, 6);
            WritePerLength(gccMs, innerGcc.Length);
            gccMs.Write(innerGcc, 0, innerGcc.Length);

            byte[] gccResponse = gccMs.ToArray();

            // 3. MCS Connect-Response [APPLICATION 102]
            using var ms = new MemoryStream();
            ms.WriteByte(0x7F);
            ms.WriteByte(0x66);

            // domainParameters (28 bytes total: 2-byte SEQUENCE header + 26 bytes content)
            byte[] domainParams = new byte[] {
                0x30, 0x1A,
                0x02, 0x01, 0x22, // maxChannelIds: 34
                0x02, 0x01, 0x03, // maxUserIds: 3
                0x02, 0x01, 0x00, // maxTokenIds: 0
                0x02, 0x01, 0x01, // numPriorities: 1
                0x02, 0x01, 0x00, // minThroughput: 0
                0x02, 0x01, 0x01, // maxHeight: 1
                0x02, 0x03, 0x00, 0xFF, 0xF8, // maxMCSPDUsize: 65528
                0x02, 0x01, 0x02  // protocolVersion: 2
            };

            int userDataHeaderLen = gccResponse.Length < 128 ? 2 : (gccResponse.Length <= 0xFF ? 3 : 4);
            int innerLength = 3 + 3 + domainParams.Length + (userDataHeaderLen + gccResponse.Length);
            WriteBerLength(ms, innerLength);

            // Result rt-successful (0)
            ms.Write(new byte[] { 0x0A, 0x01, 0x00 }, 0, 3);
            // calledConnectId
            ms.Write(new byte[] { 0x02, 0x01, 0x00 }, 0, 3);
            // domainParameters
            ms.Write(domainParams, 0, domainParams.Length);

            // UserData (OCTET STRING)
            ms.WriteByte(0x04);
            WriteBerLength(ms, gccResponse.Length);
            ms.Write(gccResponse, 0, gccResponse.Length);

            return WrapTpktX224Data(ms.ToArray());
        }

        private static void WritePerLength(Stream stream, int length)
        {
            if (length < 128)
            {
                stream.WriteByte((byte)length);
            }
            else
            {
                stream.WriteByte((byte)((length >> 8) | 0x80));
                stream.WriteByte((byte)(length & 0xFF));
            }
        }

        public static byte[] BuildMcsAttachUserConfirm(ushort userId = 1002)
        {
            // In PER integer16 with min=MCS_BASE_CHANNEL_ID (1001):
            // value encoded is (userId - 1001)
            ushort userOffset = (ushort)(userId - 1001);
            byte[] mcsPayload = new byte[] {
                RdpProtocolConstants.MCS_ATTACH_USER_CONFIRM, // 0x2E
                0x00, // result = rt-successful
                (byte)((userOffset >> 8) & 0xFF),
                (byte)(userOffset & 0xFF)
            };
            return WrapTpktX224Data(mcsPayload);
        }

        public static byte[] BuildMcsChannelJoinConfirm(ushort initiator, ushort channelId)
        {
            // initiator is encoded with min=1001 -> (initiator - 1001)
            // requested & channelId are encoded with min=0 -> channelId
            ushort userOffset = (ushort)(initiator - 1001);
            byte[] mcsPayload = new byte[] {
                RdpProtocolConstants.MCS_CHANNEL_JOIN_CONFIRM, // 0x3E
                0x00, // result = rt-successful
                (byte)((userOffset >> 8) & 0xFF),
                (byte)(userOffset & 0xFF),
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

            // Security Header (4 bytes): SEC_LICENSE_PKT (0x0080)
            ms.Write(new byte[] { 0x80, 0x00, 0x00, 0x00 }, 0, 4);

            // License Error PDU (16 bytes):
            // bMsgType = ERROR_ALERT (0xFF)
            ms.WriteByte(0xFF);
            // flags = PREAMBLE_VERSION_3_0 (0x03)
            ms.WriteByte(0x03);
            // wMsgSize = 16 (0x10, 0x00)
            ms.Write(new byte[] { 0x10, 0x00 }, 0, 2);
            // dwErrorCode = STATUS_VALID_CLIENT (0x00000007)
            ms.Write(new byte[] { 0x07, 0x00, 0x00, 0x00 }, 0, 4);
            // dwStateTransition = ST_NO_TRANSITION (0x00000002)
            ms.Write(new byte[] { 0x02, 0x00, 0x00, 0x00 }, 0, 4);
            // bbErrorInfo = wBlobType=0, wBlobLen=0
            ms.Write(new byte[] { 0x00, 0x00, 0x00, 0x00 }, 0, 4);

            return WrapSendDataIndication(ms.ToArray(), 1002, 1003);
        }

        public static byte[] BuildDemandActivePDU(int width, int height, ushort bpp = 24)
        {
            using var capMs = new MemoryStream();

            // 1. General Capability Set (24 bytes)
            capMs.Write(new byte[] {
                0x01, 0x00, 0x18, 0x00, // type=1, len=24
                0x01, 0x00, // osMajorType = OSMAJORTYPE_WINDOWS (1)
                0x03, 0x00, // osMinorType = OSMINORTYPE_WINDOWS_NT (3)
                0x00, 0x02, // protocolVersion = TS_CAPS_PROTOCOLVERSION (0x0200)
                0x00, 0x00, // pad2OctetsA
                0x00, 0x00, // generalCompressionTypes
                0x0D, 0x04, // extraFlags = 0x040D (FASTPATH_OUTPUT_SUPPORTED | NO_BITMAP_COMPRESSION_HDR | LONG_CREDENTIALS | AUTORECONNECT)
                0x00, 0x00, // updateCapabilityFlag
                0x00, 0x00, // remoteUnshareFlag
                0x00, 0x00, // generalCompressionLevel
                0x01,       // refreshRectSupport = 1
                0x01        // suppressOutputSupport = 1
            }, 0, 24);

            // 2. Bitmap Capability Set (28 bytes)
            capMs.Write(new byte[] {
                0x02, 0x00, 0x1C, 0x00, // type=2, len=28
                (byte)(bpp & 0xFF), (byte)((bpp >> 8) & 0xFF), // preferredBitsPerPixel
                0x01, 0x00, // receive1BitPerPixel = 1
                0x01, 0x00, // receive4BitsPerPixel = 1
                0x01, 0x00, // receive8BitsPerPixel = 1
                (byte)(width & 0xFF), (byte)((width >> 8) & 0xFF),   // desktopWidth
                (byte)(height & 0xFF), (byte)((height >> 8) & 0xFF), // desktopHeight
                0x00, 0x00, // pad2Octets
                0x01, 0x00, // desktopResizeFlag = 1
                0x01, 0x00, // bitmapCompressionFlag = 1
                0x00,       // highColorFlags = 0
                0x08,       // drawingFlags = DRAW_ALLOW_DYNAMIC_COLOR_FIDELITY (0x08)
                0x01, 0x00, // multipleRectangleSupport = 1
                0x00, 0x00  // pad2OctetsB
            }, 0, 28);

            // 3. Order Capability Set (88 bytes)
            byte[] orderCap = new byte[88];
            orderCap[0] = 0x03; orderCap[1] = 0x00; // type = 3
            orderCap[2] = 88; orderCap[3] = 0x00;   // length = 88
            orderCap[24] = 0x01; orderCap[26] = 20; // granularity
            orderCap[30] = 0x01;                    // maximumOrderLevel = 1
            orderCap[34] = 0x2A;                    // orderFlags (NEGOTIATEORDERSUPPORT | ZEROBOUNDSDELTASSUPPORT | COLORINDEXSUPPORT)
            orderCap[76] = 0x00; orderCap[77] = 0x84; orderCap[78] = 0x03; orderCap[79] = 0x00; // desktopSaveSize = 230400
            capMs.Write(orderCap, 0, orderCap.Length);

            // 4. Pointer Capability Set (10 bytes)
            capMs.Write(new byte[] {
                0x08, 0x00, 0x0A, 0x00, // type=8, len=10
                0x01, 0x00, // colorPointerFlag = 1
                0x14, 0x00, // colorPointerCacheSize = 20
                0x14, 0x00  // pointerCacheSize = 20
            }, 0, 10);

            // 5. Input Capability Set (88 bytes)
            byte[] inputCap = new byte[88];
            inputCap[0] = 0x0D; inputCap[1] = 0x00; // type = 13
            inputCap[2] = 88; inputCap[3] = 0x00;   // length = 88
            inputCap[4] = 0x35; inputCap[5] = 0x00; // inputFlags = 0x0035 (SCANCODES | FASTPATH | FASTPATH2 | UNICODE)
            inputCap[8] = 0x09; inputCap[9] = 0x04; // keyboardLayout = 0x0409 (US English)
            inputCap[12] = 0x04;                    // keyboardType = 4
            inputCap[20] = 12;                      // functionKeys = 12
            capMs.Write(inputCap, 0, inputCap.Length);

            // 6. Virtual Channel Capability Set (8 bytes)
            capMs.Write(new byte[] {
                0x14, 0x00, 0x08, 0x00, // type=20, len=8
                0x00, 0x00, 0x00, 0x00  // flags = VCCAPS_NO_COMPR
            }, 0, 8);

            // 7. Share Capability Set (8 bytes)
            capMs.Write(new byte[] {
                0x09, 0x00, 0x08, 0x00, // type=9, len=8
                0xEA, 0x03,             // nodeId = 1002 (0x03EA)
                0x00, 0x00              // pad2Octets
            }, 0, 8);

            // 8. Color Cache Capability Set (8 bytes)
            capMs.Write(new byte[] {
                0x0A, 0x00, 0x08, 0x00, // type=10, len=8
                0x06, 0x00,             // colorTableCacheSize = 6
                0x00, 0x00              // pad2Octets
            }, 0, 8);

            // 9. Font Capability Set (8 bytes)
            capMs.Write(new byte[] {
                0x0E, 0x00, 0x08, 0x00, // type=14, len=8
                0x01, 0x00,             // fontSupportFlags = FONTSUPPORT_FONTLIST (1)
                0x00, 0x00              // pad2Octets
            }, 0, 8);

            byte[] capsData = capMs.ToArray();
            ushort combinedCapsLen = (ushort)(4 + capsData.Length); // numberCapabilities (2) + pad2Octets (2) + capsData

            using var pduMs = new MemoryStream();
            // Share Control Header (6 bytes) + DemandActive body (16 + capsData.Length + 4 sessionId)
            ushort totalLen = (ushort)(6 + 16 + capsData.Length + 4);
            pduMs.WriteByte((byte)(totalLen & 0xFF));
            pduMs.WriteByte((byte)((totalLen >> 8) & 0xFF));
            pduMs.WriteByte(0x11); // TS_PDUTYPE_DEMANDACTIVEPDU
            pduMs.WriteByte(0x00);
            pduMs.Write(new byte[] { 0xEA, 0x03 }, 0, 2); // pduSource = 1002 (0x03EA)

            // Demand Active PDU data (16 bytes + capsData.Length + 4 bytes sessionId)
            pduMs.Write(new byte[] { 0xEA, 0x03, 0x01, 0x00 }, 0, 4); // shareId = 0x000103EA
            pduMs.Write(new byte[] { 0x04, 0x00 }, 0, 2); // lengthSourceDescriptor = 4
            pduMs.Write(new byte[] { (byte)(combinedCapsLen & 0xFF), (byte)((combinedCapsLen >> 8) & 0xFF) }, 0, 2);
            pduMs.Write(Encoding.ASCII.GetBytes("RDP\0"), 0, 4); // sourceDescriptor
            pduMs.Write(new byte[] { 0x09, 0x00, 0x00, 0x00 }, 0, 4); // numberCapabilities = 9, pad2Octets = 0
            pduMs.Write(capsData, 0, capsData.Length);
            pduMs.Write(new byte[] { 0x00, 0x00, 0x00, 0x00 }, 0, 4); // sessionId = 0

            return WrapSendDataIndication(pduMs.ToArray(), 1002, 1003);
        }

        public static byte[] BuildSynchronizePDU(uint shareId = 0x000103EA, ushort userId = 1002)
        {
            using var ms = new MemoryStream();
            // Share Control Header (6 bytes)
            ms.Write(new byte[] {
                0x16, 0x00, // totalLength = 22 (6 + 12 + 4)
                0x17, 0x00, // TS_PDUTYPE_DATAPDU
                0xEA, 0x03  // pduSource = 1002
            }, 0, 6);

            // Share Data Header (12 bytes)
            ms.Write(BitConverter.GetBytes(shareId), 0, 4); // shareId
            ms.WriteByte(0x00); // pad1
            ms.WriteByte(0x01); // streamId = STREAM_LOW
            ms.Write(new byte[] { 0x04, 0x00 }, 0, 2); // uncompressedLength = 4
            ms.WriteByte(0x1F); // pduType2 = TS_PDUTYPE2_SYNCHRONIZE
            ms.WriteByte(0x00); // compressedType = 0
            ms.Write(new byte[] { 0x00, 0x00 }, 0, 2); // compressedLength = 0

            // Synchronize Payload (4 bytes)
            ms.Write(new byte[] { 0x01, 0x00 }, 0, 2); // messageType = SYNCMSGTYPE_SYNC (1)
            ms.Write(BitConverter.GetBytes(userId), 0, 2); // targetUser

            return WrapSendDataIndication(ms.ToArray(), 1002, 1003);
        }

        public static byte[] BuildControlPDU(ushort action, ushort grantId = 0, uint controlId = 0, uint shareId = 0x000103EA)
        {
            using var ms = new MemoryStream();
            // Share Control Header (6 bytes)
            ms.Write(new byte[] {
                0x1A, 0x00, // totalLength = 26 (6 + 12 + 8)
                0x17, 0x00, // TS_PDUTYPE_DATAPDU
                0xEA, 0x03  // pduSource = 1002
            }, 0, 6);

            // Share Data Header (12 bytes)
            ms.Write(BitConverter.GetBytes(shareId), 0, 4); // shareId
            ms.WriteByte(0x00); // pad1
            ms.WriteByte(0x01); // streamId = STREAM_LOW
            ms.Write(new byte[] { 0x08, 0x00 }, 0, 2); // uncompressedLength = 8
            ms.WriteByte(0x14); // pduType2 = TS_PDUTYPE2_CONTROL
            ms.WriteByte(0x00); // compressedType = 0
            ms.Write(new byte[] { 0x00, 0x00 }, 0, 2); // compressedLength = 0

            // Control Payload (8 bytes)
            ms.Write(BitConverter.GetBytes(action), 0, 2); // action
            ms.Write(BitConverter.GetBytes(grantId), 0, 2); // grantId
            ms.Write(BitConverter.GetBytes(controlId), 0, 4); // controlId

            return WrapSendDataIndication(ms.ToArray(), 1002, 1003);
        }

        public static byte[] BuildFontMapPDU(uint shareId = 0x000103EA)
        {
            using var ms = new MemoryStream();
            // Share Control Header (6 bytes)
            ms.Write(new byte[] {
                0x1A, 0x00, // totalLength = 26 (6 + 12 + 8)
                0x17, 0x00, // TS_PDUTYPE_DATAPDU
                0xEA, 0x03  // pduSource = 1002
            }, 0, 6);

            // Share Data Header (12 bytes)
            ms.Write(BitConverter.GetBytes(shareId), 0, 4); // shareId
            ms.WriteByte(0x00); // pad1
            ms.WriteByte(0x01); // streamId = STREAM_LOW
            ms.Write(new byte[] { 0x08, 0x00 }, 0, 2); // uncompressedLength = 8
            ms.WriteByte(0x28); // pduType2 = TS_PDUTYPE2_FONTMAP
            ms.WriteByte(0x00); // compressedType = 0
            ms.Write(new byte[] { 0x00, 0x00 }, 0, 2); // compressedLength = 0

            // Font Map Payload (8 bytes)
            ms.Write(new byte[] { 0x00, 0x00 }, 0, 2); // numberEntries = 0
            ms.Write(new byte[] { 0x00, 0x00 }, 0, 2); // totalNumEntries = 0
            ms.Write(new byte[] { 0x03, 0x00 }, 0, 2); // mapFlags = 3 (FIRST | LAST)
            ms.Write(new byte[] { 0x04, 0x00 }, 0, 2); // entrySize = 4

            return WrapSendDataIndication(ms.ToArray(), 1002, 1003);
        }

        public static byte[] BuildSystemPointerPDU(uint systemPointerType = 0x00007F00, uint shareId = 0x000103EA)
        {
            using var ms = new MemoryStream();
            // Share Control Header (6 bytes)
            ms.Write(new byte[] {
                0x1A, 0x00, // totalLength = 26 (6 + 12 + 8)
                0x17, 0x00, // TS_PDUTYPE_DATAPDU
                0xEA, 0x03  // pduSource = 1002
            }, 0, 6);

            // Share Data Header (12 bytes)
            ms.Write(BitConverter.GetBytes(shareId), 0, 4); // shareId
            ms.WriteByte(0x00); // pad1
            ms.WriteByte(0x01); // streamId = STREAM_LOW
            ms.Write(new byte[] { 0x08, 0x00 }, 0, 2); // uncompressedLength = 8
            ms.WriteByte(0x1B); // pduType2 = TS_PDUTYPE2_POINTER
            ms.WriteByte(0x00); // compressedType = 0
            ms.Write(new byte[] { 0x00, 0x00 }, 0, 2); // compressedLength = 0

            // Pointer Payload (8 bytes): messageType = TS_PTRMSGTYPE_SYSTEM (1), pad2Octets = 0, systemPointerType = SYSPTR_DEFAULT (0x00007F00)
            ms.Write(new byte[] { 0x01, 0x00, 0x00, 0x00 }, 0, 4);
            ms.Write(BitConverter.GetBytes(systemPointerType), 0, 4);

            return WrapSendDataIndication(ms.ToArray(), 1002, 1003);
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

        public static string ExtractCookieUsername(byte[] data, int offset, int length)
        {
            try
            {
                string ascii = Encoding.ASCII.GetString(data, offset, length);
                const string marker = "Cookie: mstshash=";
                int idx = ascii.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
                if (idx >= 0)
                {
                    int start = idx + marker.Length;
                    int end = ascii.IndexOf("\r\n", start, StringComparison.Ordinal);
                    if (end > start)
                    {
                        return ascii[start..end].Trim();
                    }
                }
            }
            catch { }
            return "";
        }

        public static (string username, string password, string domain) ExtractCredentialsFromInfoPacket(byte[] data, int offset, int length)
        {
            try
            {
                int end = offset + length;

                // 1. Standard MS-RDPBCGR TS_INFO_PACKET:
                // Preceded by SEC_INFO_PKT (0x0040, 0x0000) or 18-byte TS_INFO_PACKET header:
                // CodePage (4), flags (4), cbDomain (2), cbUserName (2), cbPassword (2), cbAlternateShell (2), cbWorkingDir (2) = 18 bytes
                // Followed by Domain + nullTerm, UserName + nullTerm, Password + nullTerm
                for (int i = offset; i <= end - 18; i++)
                {
                    // Prefer offset right after SEC_INFO_PKT (0x40, 0x00, 0x00, 0x00) if present
                    bool hasSecHeader = i >= offset + 4 &&
                                        data[i - 4] == 0x40 && data[i - 3] == 0x00 &&
                                        data[i - 2] == 0x00 && data[i - 1] == 0x00;

                    uint flags = BitConverter.ToUInt32(data, i + 4);
                    ushort cbDomain = BitConverter.ToUInt16(data, i + 8);
                    ushort cbUserName = BitConverter.ToUInt16(data, i + 10);
                    ushort cbPassword = BitConverter.ToUInt16(data, i + 12);
                    ushort cbAltShell = BitConverter.ToUInt16(data, i + 14);
                    ushort cbWorkDir = BitConverter.ToUInt16(data, i + 16);

                    bool isUnicode = (flags & RdpProtocolConstants.INFO_UNICODE) != 0;
                    int nullTerm = isUnicode ? 2 : 1;

                    if (cbDomain <= 512 && cbUserName <= 512 && cbPassword <= 512 && cbAltShell <= 512 && cbWorkDir <= 512 &&
                        (hasSecHeader || (cbUserName > 0 && (!isUnicode || (cbDomain % 2 == 0 && cbUserName % 2 == 0)))))
                    {
                        int domainPos = i + 18;
                        int domainNullPos = domainPos + cbDomain;
                        int userPos = domainNullPos + nullTerm;
                        int userNullPos = userPos + cbUserName;
                        int passPos = userNullPos + nullTerm;
                        int passEnd = passPos + cbPassword;

                        if (passEnd + nullTerm <= end)
                        {
                            // Verify mandatory null terminators after Domain and UserName
                            bool validDomainNull = data[domainNullPos] == 0 && (nullTerm == 1 || data[domainNullPos + 1] == 0);
                            bool validUserNull = data[userNullPos] == 0 && (nullTerm == 1 || data[userNullPos + 1] == 0);

                            if (validDomainNull && validUserNull)
                            {
                                var enc = isUnicode ? Encoding.Unicode : Encoding.ASCII;
                                string domain = cbDomain > 0 ? enc.GetString(data, domainPos, cbDomain).TrimEnd('\0') : "";
                                string username = cbUserName > 0 ? enc.GetString(data, userPos, cbUserName).TrimEnd('\0') : "";
                                string password = DecodePassword(data, passPos, cbPassword, flags, enc);

                                if (hasSecHeader || (!string.IsNullOrEmpty(username) && !username.Contains('\0')))
                                {
                                    return (username, password, domain);
                                }
                            }
                        }
                    }
                }

                // 2. Fallback for compact/synthetic TS_INFO_PACKET without null terminators (16-byte header)
                for (int i = offset; i <= end - 16; i++)
                {
                    uint flags = BitConverter.ToUInt32(data, i + 2);
                    ushort cbDomain = BitConverter.ToUInt16(data, i + 6);
                    ushort cbUserName = BitConverter.ToUInt16(data, i + 8);
                    ushort cbPassword = BitConverter.ToUInt16(data, i + 10);

                    if (cbDomain <= 256 && cbUserName > 0 && cbUserName <= 256 && cbPassword <= 512)
                    {
                        int payloadStart = i + 16;
                        if (payloadStart + cbDomain + cbUserName + cbPassword <= end)
                        {
                            bool isUnicode = (flags & RdpProtocolConstants.INFO_UNICODE) != 0;
                            var enc = isUnicode ? Encoding.Unicode : Encoding.ASCII;

                            string domain = cbDomain > 0 ? enc.GetString(data, payloadStart, cbDomain).TrimEnd('\0') : "";
                            string username = enc.GetString(data, payloadStart + cbDomain, cbUserName).TrimEnd('\0');
                            string password = DecodePassword(data, payloadStart + cbDomain + cbUserName, cbPassword, flags, enc);

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

        private static string DecodePassword(byte[] data, int passOffset, ushort cbPassword, uint flags, Encoding enc)
        {
            if (cbPassword == 0 || passOffset + cbPassword > data.Length)
            {
                return "";
            }

            // Note: 0x00000020 in MS-RDPBCGR is INFO_MAXIMIZESHELL (set by mstsc/FreeRDP/Hydra).
            // Only apply 0xA5 descrambling if the payload actually contains 0xA5-masked bytes.
            if ((flags & RdpProtocolConstants.INFO_PASSWORD_IS_SCRAMBLED) != 0 && passOffset + 4 <= data.Length)
            {
                ushort actualLen = BitConverter.ToUInt16(data, passOffset);
                if (actualLen > 0 && actualLen <= 510 &&
                    actualLen == cbPassword - 2 &&
                    passOffset + 2 + actualLen <= data.Length &&
                    data[passOffset + 3] == 0xA5)
                {
                    byte[] descrambled = new byte[actualLen];
                    for (int b = 0; b < actualLen; b++)
                    {
                        descrambled[b] = (byte)(data[passOffset + 2 + b] ^ 0xA5);
                    }
                    return enc.GetString(descrambled).TrimEnd('\0');
                }
            }

            return enc.GetString(data, passOffset, cbPassword).TrimEnd('\0');
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
