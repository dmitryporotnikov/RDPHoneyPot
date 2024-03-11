using System;
using System.Data.SQLite;
using System.IO;

namespace RDPHoney
{
    // Purpose: Manages the logging of RDP connection attempts to a SQLite database for an RDP honeypot application.
    // Properties: dbFileName(string), connectionString(string)
    // Methods: InitializeDatabase(), LogConnection(string ipAddress, string type), CheckIfRdpClientExists(string ipAddress)
    //----
    // dbFileName(string) - The name of the SQLite database file.
    // connectionString(string) - The SQLite connection string used to connect to the database.
    // InitializeDatabase() - Checks if the database file exists; if not, it creates the file and the ConnectionLogs table.
    // LogConnection(string ipAddress, string type) - Logs a new connection attempt to the database with the provided IP address, current timestamp, and type of connection.
    // CheckIfRdpClientExists(string ipAddress) - Checks the database to see if there is an existing entry for the given IP address with the type 'RDPClient'.
    //
    // Dmitry Porotnikov

    public static class DatabaseLogger
    {
        private static string dbFileName = "RdpHoneypotLogs.db";
        private static string connectionString = $"Data Source={dbFileName};Version=3;";

        public static void InitializeDatabase()
        {
            if (!File.Exists(dbFileName))
            {
                SQLiteConnection.CreateFile(dbFileName);
                using (var connection = new SQLiteConnection(connectionString))
                {
                    connection.Open();
                    using (var command = new SQLiteCommand(connection))
                    {
                        command.CommandText = @"
                        CREATE TABLE IF NOT EXISTS ConnectionLogs (
                            Id INTEGER PRIMARY KEY AUTOINCREMENT,
                            IPAddress TEXT NOT NULL,
                            Timestamp DATETIME NOT NULL,
                            Type TEXT NOT NULL
                        )";
                        command.ExecuteNonQuery();
                    }
                }
            }
        }

        public static void LogConnection(string ipAddress, string type)
        {
            using (var connection = new SQLiteConnection(connectionString))
            {
                connection.Open();
                using (var command = new SQLiteCommand(connection))
                {
                    command.CommandText = "INSERT INTO ConnectionLogs (IPAddress, Timestamp, Type) VALUES (@IPAddress, @Timestamp, @Type)";
                    command.Parameters.AddWithValue("@IPAddress", ipAddress);
                    command.Parameters.AddWithValue("@Timestamp", DateTime.UtcNow);
                    command.Parameters.AddWithValue("@Type", type);
                    command.ExecuteNonQuery();
                }
            }
        }
        public static bool CheckIfRdpClientExists(string ipAddress)
        {
            using (var connection = new SQLiteConnection(connectionString))
            {
                connection.Open();
                using (var command = new SQLiteCommand(connection))
                {
                    command.CommandText = "SELECT COUNT(*) FROM ConnectionLogs WHERE IPAddress = @IPAddress AND Type = 'RDPClient'";
                    command.Parameters.AddWithValue("@IPAddress", ipAddress);

                    var result = command.ExecuteScalar();
                    return Convert.ToInt32(result) > 0;
                }
            }
        }

    }
}
