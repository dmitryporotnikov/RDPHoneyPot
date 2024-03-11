using System;
using System.Data.SQLite;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace RDPHoney
{
    // Purpose: Implements handling of TCP clients connecting to an RDP honeypot server, simulating RDP handshake and logging activities.
    // Interface: IRdpPacketHandler
    // Methods: HandleClient(TcpClient client), ReadX224ConnectionRequest(NetworkStream stream), SendX224ConnectionConfirm(NetworkStream stream, TcpClient client), ReadMCSConnectInitial(NetworkStream stream, TcpClient client), SendMCSConnectResponse(NetworkStream stream, TcpClient client)
    //----
    // IRdpPacketHandler
    // - HandleClient(TcpClient client): Entrypoint for handling an incoming RDP connection attempt.
    //
    // RdpConnectionHandler : IRdpPacketHandler
    // - HandleClient(TcpClient client): Handles the incoming TCP client connection, performs initial checks for previous activity from the client IP, and attempts to simulate an RDP handshake process.
    // - ReadX224ConnectionRequest(NetworkStream stream): Reads the X.224 Connection Request packet from the client, validating the start of the RDP handshake.
    // - SendX224ConnectionConfirm(NetworkStream stream, TcpClient client): Sends a mock X.224 Connection Confirm packet to the client, simulating the next step of the RDP handshake.
    // - ReadMCSConnectInitial(NetworkStream stream, TcpClient client): Reads the MCS Connect Initial packet from the client, further simulating the RDP handshake process.
    // - SendMCSConnectResponse(NetworkStream stream, TcpClient client): Sends a simplified MCS Connect Response packet, completing the simulation of the RDP handshake for non-compliant or scanner-type clients.
    //
    // Details:
    // The RdpConnectionHandler class implements the IRdpPacketHandler interface, defining a structured approach to handle RDP connection attempts. The primary method, HandleClient, orchestrates the simulation of an RDP handshake process, starting from the initial connection attempt, through various stages of the RDP protocol, and concludes by logging the attempt and optionally sending responses that might trigger certain behaviors in scanning software or malicious actors. The class is designed to work in conjunction with the DatabaseLogger class to log connection attempts and determine if the source IP has previously engaged in RDP-related activities. This mechanism allows for dynamic response strategies based on past interactions, enhancing the honeypot's capability to mimic real-world RDP server behaviors and potentially identifying malicious entities.
    //
    // Dmitry Porotnikov


    public interface IRdpPacketHandler
    {
        void HandleClient(TcpClient client);
    }

    public class RdpConnectionHandler : IRdpPacketHandler
    {
        public void HandleClient(TcpClient client)
        {
            string clientIP = ((IPEndPoint)client.Client.RemoteEndPoint).Address.ToString();
            if (DatabaseLogger.CheckIfRdpClientExists(clientIP))
            {
                // If exists, silently drop the connection by not responding and closing the stream.
                Console.WriteLine($"Connection from {clientIP} dropped due to previous RDPClient activity.");
                client.Close();
                return; // Exit the method, effectively dropping the connection silently.
            }

            using (var clientStream = client.GetStream())
            {
                try
                {
                    ReadX224ConnectionRequest(clientStream);
                    SendX224ConnectionConfirm(clientStream, client);
                    ReadMCSConnectInitial(clientStream, client);
                    SendMCSConnectResponse(clientStream, client);
                }
                catch (Exception e)
                {
                    Console.WriteLine($"Error handling RDP client: {e.Message}");
                }
            }
        }

        private void ReadX224ConnectionRequest(NetworkStream stream)
        {
            byte[] buffer = new byte[1024];
            int bytesRead = 0;

            try
            {
                bytesRead = stream.Read(buffer, 0, buffer.Length);
                if (bytesRead > 0)
                {
                    Console.WriteLine("Received X.224 Connection Request");
                }
                else
                {
                    throw new Exception("No data received in connection request.");
                }
            }
            catch (IOException e)
            {
                Console.WriteLine($"Network error reading X.224 request: {e.Message}");
                throw;
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error reading X.224 request: {e.Message}");
                throw;
            }
        }

       private void SendX224ConnectionConfirm(NetworkStream stream, TcpClient client)
        {
            // Construct the TPKT Header: Version 3, Reserved 0, Length
            byte[] tpktHeader = new byte[] { 0x03, 0x00, 0x00, 0x00 };

            // X.224 Connection Confirm (CC) TPDU
            byte[] x224Ccf = new byte[] {
        0x06, // Length Indicator: Includes x224Ccf and following bytes
        (byte)0xD0, // CR - Connect Confirm
        0, 0, // Destination Reference (0 = not used)
        0x12, 0x34, // Source Reference (should be echoed from Connection Request)
        0, // Class and Options (Class 0, no options)
        };

            // Assuming the security protocol negotiation is successful and opting for standard RDP security
            byte[] rdpNegData = new byte[] {
        0x02, // RDP Negotiation Response type
        0x08, // Flags: PROTOCOL_SSL supported
        0x00, 0x08, // Length (8 bytes including this header)
        0x01, 0x00, 0x00, 0x00 // Selected Protocol: PROTOCOL_SSL
        };

            // Calculate the total length
            int totalLength = tpktHeader.Length + x224Ccf.Length + rdpNegData.Length - 4; // Exclude the size of tpktHeader itself
            tpktHeader[2] = (byte)((totalLength >> 8) & 0xFF); // High byte of length
            tpktHeader[3] = (byte)(totalLength & 0xFF); // Low byte of length

            // Combine all parts into one packet
            byte[] packet = new byte[totalLength + 4]; // Include the size of tpktHeader
            Buffer.BlockCopy(tpktHeader, 0, packet, 0, tpktHeader.Length);
            Buffer.BlockCopy(x224Ccf, 0, packet, tpktHeader.Length, x224Ccf.Length);
            Buffer.BlockCopy(rdpNegData, 0, packet, tpktHeader.Length + x224Ccf.Length, rdpNegData.Length);

            try
    {
        stream.Write(packet, 0, packet.Length);
        stream.Flush();
        Console.WriteLine("Sent X.224 Connection Confirm with RDP Negotiation Response.");
    }
    catch (Exception e)
    {
        Console.WriteLine($"Error sending X.224 Connection Confirm: {e.Message}");
    }
        }


        private void ReadMCSConnectInitial(NetworkStream stream, TcpClient client)
        {
            byte[] buffer = new byte[4096];
            int bytesReadTotal = 0;

            try
            {
                bytesReadTotal = stream.Read(buffer, 0, buffer.Length);
                if (bytesReadTotal > 0)
                {
                    Console.WriteLine("Received MCS Connect Initial packet");
                }
                else
                {
                    throw new Exception("No data received in MCS Connect Initial.");
                }
            }
            catch (IOException e)
            {
                Console.WriteLine($"Network error reading MCS Connect Initial: {e.Message}. Peer is most likely RDP client and reset connection as we just sent wrong SendX224ConnectionConfirm");
                DatabaseLogger.LogConnection(((IPEndPoint)client.Client.RemoteEndPoint).Address.ToString(), "RDPClient");

                throw;
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error reading MCS Connect Initial: {e.Message}");
                throw;
            }
        }

        private void SendMCSConnectResponse(NetworkStream stream, TcpClient client)
        {
            //not protocol complient, but scaner should eat that
            byte[] tpktHeader = new byte[] { 0x03, 0x00 };
            byte[] lengthPlaceholder = new byte[] { 0x01, 0x00 }; 

            byte[] x224Header = new byte[] { 0x02, (byte)0xF0, (byte)0x80 }; // X.224 Data TPDU Header

            byte[] mcsConnectResponse = Encoding.ASCII.GetBytes("MCS Connect Response");

            // Combine parts to form the complete packet
            byte[] packet = new byte[tpktHeader.Length + lengthPlaceholder.Length + x224Header.Length + mcsConnectResponse.Length];

            // Copy parts into the packet
            int offset = 0;
            Buffer.BlockCopy(tpktHeader, 0, packet, offset, tpktHeader.Length);
            offset += tpktHeader.Length;
            Buffer.BlockCopy(lengthPlaceholder, 0, packet, offset, lengthPlaceholder.Length);
            offset += lengthPlaceholder.Length;
            Buffer.BlockCopy(x224Header, 0, packet, offset, x224Header.Length);
            offset += x224Header.Length;
            Buffer.BlockCopy(mcsConnectResponse, 0, packet, offset, mcsConnectResponse.Length);

            // Calculate and set the actual packet length (TPKT total length)
            int packetLength = packet.Length;
            packet[2] = (byte)((packetLength >> 8) & 0xFF); // Length high byte
            packet[3] = (byte)(packetLength & 0xFF); // Length low byte

            try
            {
                stream.Write(packet, 0, packet.Length);
                stream.Flush();
                Console.WriteLine("Sent simplified MCS Connect Response. Peer is most likely a port scanner");
                DatabaseLogger.LogConnection(((IPEndPoint)client.Client.RemoteEndPoint).Address.ToString(), "PortScanner");
                stream.Close();
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error sending MCS Connect Response: {e.Message}");
                stream.Close();
            }
        }

    }


}
