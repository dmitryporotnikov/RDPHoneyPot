using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using RDPHoney;

namespace RDPHoney
{
    public class EnhancedRDPServerHoneypot
    {
        // Purpose: Implements an enhanced RDP server honeypot to simulate an RDP service, detect, and log unauthorized RDP connection attempts.
        // Properties: listener(TcpListener), Port(int)
        // Methods: EnhancedRDPServerHoneypot(), Start()
        //----
        // listener(TcpListener) - A TcpListener instance used to listen for incoming TCP connection requests on a specified port.
        // Port(int) - The port number (default 3389) on which the server listens for incoming RDP connection requests.
        // EnhancedRDPServerHoneypot() - Constructor that initializes the TcpListener with IPAddress.Any, allowing it to accept connection requests on any network interface.
        // Start() - Starts the TcpListener to accept incoming RDP connection requests and creates a new thread for each connection to handle the RDP handshake and subsequent interaction.
        //
        // Dmitry Porotnikkov

        private TcpListener listener;
        private const int Port = 3389;

        public EnhancedRDPServerHoneypot()
        {
            listener = new TcpListener(IPAddress.Any, Port);
        }

        public void Start()
        {
            listener.Start();
            Console.WriteLine($"Listening for RDP connections on port {Port}...");

            while (true)
            {
                try
                {
                    var client = listener.AcceptTcpClient();
                    Console.WriteLine("Client connected. Starting RDP handshake...");

                    var clientThread = new Thread(() => new RdpConnectionHandler().HandleClient(client));
                    clientThread.Start();
                }
                catch (Exception e)
                {
                    Console.WriteLine($"Error accepting client: {e.Message}");
                }
            }
        }
    }
}