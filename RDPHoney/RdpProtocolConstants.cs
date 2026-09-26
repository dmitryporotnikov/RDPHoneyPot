using System;

namespace RDPHoney
{
    // Purpose: Defines protocol constants, PDU types, and flags for RDP (MS-RDPBCGR).
    //
    // Dmitry Porotnikov

    public static class RdpProtocolConstants
    {
        // TPKT & X.224
        public const byte TPKT_VERSION = 0x03;
        public const byte X224_TPDU_CR = 0xE0; // Connection Request
        public const byte X224_TPDU_CC = 0xD0; // Connection Confirm
        public const byte X224_TPDU_DT = 0xF0; // Data

        // RDP Negotiation Protocols
        public const uint PROTOCOL_RDP = 0x00000000;
        public const uint PROTOCOL_SSL = 0x00000001;
        public const uint PROTOCOL_HYBRID = 0x00000002;
        public const uint PROTOCOL_HYBRID_EX = 0x00000008;

        // RDP Negotiation Messages
        public const byte RDP_NEG_REQ = 0x01;
        public const byte RDP_NEG_RSP = 0x02;
        public const byte RDP_NEG_FAILURE = 0x03;

        // MCS PDUs
        public const byte MCS_ATTACH_USER_REQUEST = 0x28;
        public const byte MCS_ATTACH_USER_CONFIRM = 0x2E;
        public const byte MCS_CHANNEL_JOIN_REQUEST = 0x38;
        public const byte MCS_CHANNEL_JOIN_CONFIRM = 0x3E;
        public const byte MCS_SEND_DATA_REQUEST = 0x64;
        public const byte MCS_SEND_DATA_INDICATION = 0x68;

        // Channels
        public const ushort MCS_USERCHANNEL_BASE = 1002;
        public const ushort MCS_IO_CHANNEL = 1003;

        // TS_INFO_PACKET flags
        public const uint INFO_UNICODE = 0x00000010;
        public const uint INFO_PASSWORD_IS_SCRAMBLED = 0x00000020;
        public const uint INFO_AUTOLOGON = 0x00000008;

        // Fast-Path
        public const byte FASTPATH_OUTPUT_ACTION_FASTPATH = 0x00;
        public const byte FASTPATH_UPDATETYPE_BITMAP = 0x01;

        public const byte FASTPATH_INPUT_EVENT_SCANCODE = 0x00;
        public const byte FASTPATH_INPUT_EVENT_MOUSE = 0x01;
        public const byte FASTPATH_INPUT_EVENT_MOUSEX = 0x02;
        public const byte FASTPATH_INPUT_EVENT_SYNC = 0x03;
        public const byte FASTPATH_INPUT_EVENT_UNICODE = 0x04;

        public const byte FASTPATH_INPUT_KBDFLAGS_RELEASE = 0x01;
        public const byte FASTPATH_INPUT_KBDFLAGS_EXTENDED = 0x02;
    }
}
