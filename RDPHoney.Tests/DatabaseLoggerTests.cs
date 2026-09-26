using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using RDPHoney;
using Xunit;

namespace RDPHoney.Tests
{
    public class DatabaseLoggerTests : IDisposable
    {
        private readonly string _testDbPath;

        public DatabaseLoggerTests()
        {
            _testDbPath = Path.Combine(Path.GetTempPath(), $"rdp_test_{Guid.NewGuid():N}.db");
            DatabaseLogger.DatabasePath = _testDbPath;
        }

        public void Dispose()
        {
            try
            {
                SqliteConnection.ClearAllPools();
                if (File.Exists(_testDbPath))
                {
                    File.Delete(_testDbPath);
                }
            }
            catch
            {
                // Best-effort cleanup
            }
        }

        [Fact]
        public void InitializeDatabase_CreatesFileAndSchema()
        {
            DatabaseLogger.InitializeDatabase();

            Assert.True(File.Exists(_testDbPath));

            using var connection = new SqliteConnection($"Data Source={_testDbPath};");
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT name FROM sqlite_master WHERE type='table' AND name='ConnectionLogs';";
            var tableName = command.ExecuteScalar() as string;

            Assert.Equal("ConnectionLogs", tableName);
        }

        [Fact]
        public void LogConnection_InsertsRecordCorrectly()
        {
            DatabaseLogger.InitializeDatabase();
            string testIp = "192.168.1.100";
            string testType = "RDPClient";

            DatabaseLogger.LogConnection(testIp, testType);

            using var connection = new SqliteConnection($"Data Source={_testDbPath};");
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT IPAddress, Type FROM ConnectionLogs WHERE IPAddress = $IPAddress;";
            command.Parameters.AddWithValue("$IPAddress", testIp);

            using var reader = command.ExecuteReader();
            Assert.True(reader.Read());
            Assert.Equal(testIp, reader.GetString(0));
            Assert.Equal(testType, reader.GetString(1));
        }

        [Fact]
        public void LogConnection_WithCredentials_InsertsUsernameAndPassword()
        {
            DatabaseLogger.InitializeDatabase();
            string testIp = "198.51.100.50";
            string testUser = "Administrator";
            string testPass = "P@ssw0rd2026!";

            DatabaseLogger.LogConnection(testIp, "RDPClient", testUser, testPass);

            using var connection = new SqliteConnection($"Data Source={_testDbPath};");
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT IPAddress, Type, Username, Password FROM ConnectionLogs WHERE IPAddress = $IPAddress;";
            command.Parameters.AddWithValue("$IPAddress", testIp);

            using var reader = command.ExecuteReader();
            Assert.True(reader.Read());
            Assert.Equal(testIp, reader.GetString(0));
            Assert.Equal("RDPClient", reader.GetString(1));
            Assert.Equal(testUser, reader.GetString(2));
            Assert.Equal(testPass, reader.GetString(3));
        }

        [Fact]
        public void CheckIfRdpClientExists_ReturnsTrueOnlyForRdpClient()
        {
            DatabaseLogger.InitializeDatabase();
            string rdpIp = "10.0.0.1";
            string scannerIp = "10.0.0.2";
            string unknownIp = "10.0.0.3";

            DatabaseLogger.LogConnection(rdpIp, "RDPClient");
            DatabaseLogger.LogConnection(scannerIp, "PortScanner");

            Assert.True(DatabaseLogger.CheckIfRdpClientExists(rdpIp));
            Assert.False(DatabaseLogger.CheckIfRdpClientExists(scannerIp));
            Assert.False(DatabaseLogger.CheckIfRdpClientExists(unknownIp));
        }

        [Fact]
        public void ConcurrentLogConnection_HandlesMultipleThreads()
        {
            DatabaseLogger.InitializeDatabase();
            int threadCount = 10;
            int insertsPerThread = 20;

            Parallel.For(0, threadCount, threadIndex =>
            {
                for (int i = 0; i < insertsPerThread; i++)
                {
                    string ip = $"192.168.{threadIndex}.{i}";
                    DatabaseLogger.LogConnection(ip, i % 2 == 0 ? "RDPClient" : "PortScanner");
                }
            });

            using var connection = new SqliteConnection($"Data Source={_testDbPath};");
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT COUNT(*) FROM ConnectionLogs;";
            long count = Convert.ToInt64(command.ExecuteScalar());

            Assert.Equal(threadCount * insertsPerThread, count);
        }
    }
}
