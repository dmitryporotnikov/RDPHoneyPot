using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace RDPHoney
{
    // Purpose: Implements an enhanced RDP server honeypot to simulate an RDP service, detect, and log unauthorized RDP connection attempts.
    // Properties: Port(int), IsRunning(bool)
    // Methods: EnhancedRDPServerHoneypot(int? port = null), Start(), Stop()
    //----
    // Port(int) - The port number (default 3389, configurable via HONEYPOT_PORT/RDP_PORT environment variable) on which the server listens.
    // EnhancedRDPServerHoneypot() - Constructor that initializes the TcpListener on IPAddress.Any.
    // Start() - Starts the TcpListener to accept incoming RDP connection requests and creates a background thread for each connection.
    // Stop() - Gracefully stops the listener and cancels accepting new connections.
    //
    // Dmitry Porotnikov

    public class EnhancedRDPServerHoneypot
    {
        private readonly TcpListener _listener;
        private readonly int _port;
        private readonly CancellationTokenSource _cts = new();
        private bool _isRunning;

        public int Port => _port;
        public bool IsRunning => _isRunning;

        public EnhancedRDPServerHoneypot(int? port = null)
        {
            _port = port ?? ResolvePort();
            _listener = new TcpListener(IPAddress.Any, _port);
        }

        public static int ResolvePort()
        {
            var envPort = Environment.GetEnvironmentVariable("HONEYPOT_PORT")
                          ?? Environment.GetEnvironmentVariable("RDP_PORT");

            if (!string.IsNullOrWhiteSpace(envPort) && int.TryParse(envPort, out int parsedPort) && parsedPort > 0 && parsedPort <= 65535)
            {
                return parsedPort;
            }

            return 3389;
        }

        public void Start()
        {
            try
            {
                _listener.Start();
                _isRunning = true;
                Console.WriteLine($"Listening for RDP connections on port {_port}...");

                while (!_cts.IsCancellationRequested)
                {
                    try
                    {
                        var client = _listener.AcceptTcpClient();
                        Console.WriteLine("Client connected. Starting RDP handshake...");

                        var clientThread = new Thread(() => new RdpConnectionHandler().HandleClient(client))
                        {
                            IsBackground = true
                        };
                        clientThread.Start();
                    }
                    catch (SocketException) when (_cts.IsCancellationRequested)
                    {
                        // Expected when listener is stopped
                        break;
                    }
                    catch (ObjectDisposedException) when (_cts.IsCancellationRequested)
                    {
                        // Expected when listener is disposed
                        break;
                    }
                    catch (Exception e)
                    {
                        if (!_cts.IsCancellationRequested)
                        {
                            Console.WriteLine($"Error accepting client: {e.Message}");
                        }
                    }
                }
            }
            finally
            {
                _isRunning = false;
                Console.WriteLine("RDP Server stopped.");
            }
        }

        public void Stop()
        {
            if (_cts.IsCancellationRequested)
            {
                return;
            }

            _cts.Cancel();
            try
            {
                _listener.Stop();
            }
            catch
            {
                // Ignore errors during stop
            }
        }
    }
}
