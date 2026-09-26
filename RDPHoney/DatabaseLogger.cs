using System;
using System.IO;
using Microsoft.Data.Sqlite;

namespace RDPHoney
{
    // Purpose: Manages the logging of RDP connection attempts and captured credentials to a SQLite database.
    // Properties: DatabasePath(string), ConnectionString(string)
    // Methods: InitializeDatabase(), LogConnection(string ipAddress, string type, string? username = null, string? password = null), CheckIfRdpClientExists(string ipAddress)
    //
    // Dmitry Porotnikov

    public static class DatabaseLogger
    {
        private static string _dbFilePath = ResolveDatabasePath();
        private static string _connectionString = $"Data Source={_dbFilePath};";
        private static readonly object _initLock = new();
        private static bool _isInitialized = false;

        public static string DatabasePath
        {
            get => _dbFilePath;
            set
            {
                lock (_initLock)
                {
                    _dbFilePath = value;
                    _connectionString = $"Data Source={_dbFilePath};";
                    _isInitialized = false;
                }
            }
        }

        public static string ConnectionString => _connectionString;

        public static string ResolveDatabasePath()
        {
            var envPath = Environment.GetEnvironmentVariable("DATABASE_PATH")
                          ?? Environment.GetEnvironmentVariable("DB_PATH");

            if (!string.IsNullOrWhiteSpace(envPath))
            {
                return envPath.Trim();
            }

            // Backward compatibility: if local file already exists, use it
            if (File.Exists("RdpHoneypotLogs.db"))
            {
                return "RdpHoneypotLogs.db";
            }

            // Default to data subdirectory (recommended for Docker volume mounting)
            return Path.Combine("data", "RdpHoneypotLogs.db");
        }

        public static void InitializeDatabase()
        {
            lock (_initLock)
            {
                var directory = Path.GetDirectoryName(_dbFilePath);
                if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                using (var connection = new SqliteConnection(_connectionString))
                {
                    connection.Open();
                    using (var command = connection.CreateCommand())
                    {
                        command.CommandText = @"
                            PRAGMA journal_mode = WAL;
                            CREATE TABLE IF NOT EXISTS ConnectionLogs (
                                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                                IPAddress TEXT NOT NULL,
                                Timestamp TEXT NOT NULL,
                                Type TEXT NOT NULL,
                                Username TEXT NULL,
                                Password TEXT NULL
                            );
                            CREATE INDEX IF NOT EXISTS IX_ConnectionLogs_IPAddress_Type 
                                ON ConnectionLogs (IPAddress, Type);
                        ";
                        command.ExecuteNonQuery();
                    }

                    // Auto-migrate schema if Username and Password columns are missing in an existing database
                    MigrateSchema(connection);
                }

                _isInitialized = true;
            }
        }

        private static void MigrateSchema(SqliteConnection connection)
        {
            try
            {
                using var checkCmd = connection.CreateCommand();
                checkCmd.CommandText = "PRAGMA table_info(ConnectionLogs);";
                using var reader = checkCmd.ExecuteReader();
                bool hasUsername = false;
                bool hasPassword = false;

                while (reader.Read())
                {
                    string colName = reader.GetString(1);
                    if (string.Equals(colName, "Username", StringComparison.OrdinalIgnoreCase)) hasUsername = true;
                    if (string.Equals(colName, "Password", StringComparison.OrdinalIgnoreCase)) hasPassword = true;
                }
                reader.Close();

                if (!hasUsername)
                {
                    using var addCol = connection.CreateCommand();
                    addCol.CommandText = "ALTER TABLE ConnectionLogs ADD COLUMN Username TEXT NULL;";
                    addCol.ExecuteNonQuery();
                }

                if (!hasPassword)
                {
                    using var addCol = connection.CreateCommand();
                    addCol.CommandText = "ALTER TABLE ConnectionLogs ADD COLUMN Password TEXT NULL;";
                    addCol.ExecuteNonQuery();
                }
            }
            catch
            {
                // Ignore migration errors if columns already exist
            }
        }

        public static void LogConnection(string ipAddress, string type, string? username = null, string? password = null)
        {
            if (!_isInitialized)
            {
                InitializeDatabase();
            }

            using (var connection = new SqliteConnection(_connectionString))
            {
                connection.Open();
                using (var command = connection.CreateCommand())
                {
                    command.CommandText = @"
                        INSERT INTO ConnectionLogs (IPAddress, Timestamp, Type, Username, Password) 
                        VALUES ($IPAddress, $Timestamp, $Type, $Username, $Password);";
                    command.Parameters.AddWithValue("$IPAddress", ipAddress);
                    command.Parameters.AddWithValue("$Timestamp", DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss.fffffffZ"));
                    command.Parameters.AddWithValue("$Type", type);
                    command.Parameters.AddWithValue("$Username", (object?)username ?? DBNull.Value);
                    command.Parameters.AddWithValue("$Password", (object?)password ?? DBNull.Value);
                    command.ExecuteNonQuery();
                }
            }
        }

        public static bool CheckIfRdpClientExists(string ipAddress)
        {
            if (!_isInitialized)
            {
                InitializeDatabase();
            }

            using (var connection = new SqliteConnection(_connectionString))
            {
                connection.Open();
                using (var command = connection.CreateCommand())
                {
                    command.CommandText = "SELECT COUNT(*) FROM ConnectionLogs WHERE IPAddress = $IPAddress AND Type = 'RDPClient';";
                    command.Parameters.AddWithValue("$IPAddress", ipAddress);

                    var result = command.ExecuteScalar();
                    return Convert.ToInt64(result) > 0;
                }
            }
        }
    }
}
