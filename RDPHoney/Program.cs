using System;
using RDPHoney;

class Program
{
    // Purpose: Main entry point for the RDP honeypot application. Initializes database and starts RDP server.
    // Usage: Called automatically by the runtime when application starts.
    // Supports graceful shutdown (SIGINT/SIGTERM/ProcessExit) for Docker and service environments.
    //
    // Dmitry Porotnikov

    static void Main(string[] args)
    {
        Console.WriteLine("==================================================");
        Console.WriteLine("  RDPHoneyPot - RDP Honeypot (.NET 10 LTS)");
        Console.WriteLine("==================================================");

        DatabaseLogger.InitializeDatabase();
        Console.WriteLine($"Database initialized: {DatabaseLogger.DatabasePath}");

        RdpScreenRenderer.EnsureDefaultStaticJpgExists();
        Console.WriteLine($"Static desktop image ready: {RdpScreenRenderer.GetStaticJpgPath()}");

        if (AbuseIpDbReporter.IsEnabled())
        {
            string? ownIp = AbuseIpDbReporter.GetOwnPublicIp();
            Console.WriteLine($"AbuseIPDB auto-reporting enabled (Categories: {AbuseIpDbReporter.GetCategories()}, Protected home IP: {ownIp ?? "private/loopback"})");
        }
        else
        {
            Console.WriteLine("AbuseIPDB auto-reporting disabled (set ABUSEIPDB_API_KEY to enable).");
        }

        var server = new EnhancedRDPServerHoneypot();

        Console.CancelKeyPress += (sender, eventArgs) =>
        {
            Console.WriteLine("\nShutdown signal received (Ctrl+C). Stopping server...");
            eventArgs.Cancel = true;
            server.Stop();
        };

        AppDomain.CurrentDomain.ProcessExit += (sender, eventArgs) =>
        {
            server.Stop();
        };

        server.Start();
    }
}
