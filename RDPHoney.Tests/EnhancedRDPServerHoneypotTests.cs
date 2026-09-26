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
    }
}
