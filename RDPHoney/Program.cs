using RDPHoney;

class Program
{
    // Purpose: Main entry point for the RDP honeypot application. Initializes the database and starts the RDP server to listen for connection attempts.
    // Usage: Called automatically by the runtime when the application is started.
    // Components: DatabaseLogger, EnhancedRDPServerHoneypot
    //----
    // Main(string[] args): The entry point of the application.
    // - DatabaseLogger.InitializeDatabase(): Initializes the SQLite database used to log RDP connection attempts. Creates the database and the necessary tables if they do not already exist.
    // - EnhancedRDPServerHoneypot server = new EnhancedRDPServerHoneypot(): Instantiates a new EnhancedRDPServerHoneypot object that listens for incoming RDP connection attempts.
    // - server.Start(): Starts the RDP server, making it listen on the default RDP port (3389) and accept incoming connections.
    //
    // This application is designed to act as a honeypot, simulating an RDP server environment to attract and log unauthorized RDP connection attempts for analysis. It uses the EnhancedRDPServerHoneypot class to manage incoming connections and the DatabaseLogger class to log connection details for future review and analysis.
    //
    // Dmitryy

    static void Main(string[] args)
    {
        DatabaseLogger.InitializeDatabase();
        var server = new EnhancedRDPServerHoneypot();
        server.Start();
    }
}
