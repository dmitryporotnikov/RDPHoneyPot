using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using RDPHoney;
using Xunit;

namespace RDPHoney.Tests
{
    [Collection("DatabaseTests")]
    public class AbuseIpDbReporterTests : IDisposable
    {
        private readonly string _testDbPath;

        public AbuseIpDbReporterTests()
        {
            _testDbPath = Path.Combine(Path.GetTempPath(), $"rdp_abuse_test_{Guid.NewGuid():N}.db");
            DatabaseLogger.DatabasePath = _testDbPath;
            DatabaseLogger.InitializeDatabase();
        }

        public void Dispose()
        {
            Environment.SetEnvironmentVariable("ABUSEIPDB_API_KEY", null);
            Environment.SetEnvironmentVariable("ABUSEIPDB_ENABLED", null);
            Environment.SetEnvironmentVariable("ABUSEIPDB_EXCLUDED_IPS", null);
            AbuseIpDbReporter.SetCachedOwnPublicIpForTesting(null);

            try
            {
                SqliteConnection.ClearAllPools();
                if (File.Exists(_testDbPath))
                {
                    File.Delete(_testDbPath);
                }
            }
            catch { }
        }

        [Theory]
        [InlineData("127.0.0.1", false)]
        [InlineData("::1", false)]
        [InlineData("10.0.0.5", false)]
        [InlineData("172.18.0.1", false)]
        [InlineData("192.168.1.100", false)]
        [InlineData("169.254.1.1", false)]
        [InlineData("100.64.0.1", false)]
        [InlineData("8.8.8.8", true)]
        [InlineData("118.25.6.39", true)]
        public void IsReportablePublicIp_FiltersPrivateLoopbackAndHomeIp(string ip, bool expected)
        {
            AbuseIpDbReporter.SetCachedOwnPublicIpForTesting("203.0.114.55");
            Assert.Equal(expected, AbuseIpDbReporter.IsReportablePublicIp(ip));
            // Verify host's own home/public IP is never reportable
            Assert.False(AbuseIpDbReporter.IsReportablePublicIp("203.0.114.55"));
        }

        [Fact]
        public void IsReportablePublicIp_HonorsExcludedIpsEnvVar()
        {
            AbuseIpDbReporter.SetCachedOwnPublicIpForTesting("203.0.114.55");
            Environment.SetEnvironmentVariable("ABUSEIPDB_EXCLUDED_IPS", "1.2.3.4, 5.6.7.8");

            Assert.False(AbuseIpDbReporter.IsReportablePublicIp("1.2.3.4"));
            Assert.False(AbuseIpDbReporter.IsReportablePublicIp("5.6.7.8"));
            Assert.True(AbuseIpDbReporter.IsReportablePublicIp("9.9.9.9"));
        }

        [Fact]
        public async Task ReportIpAsync_ReportsPublicIpAndUpdatesDatabaseAndHonorsCooldown()
        {
            AbuseIpDbReporter.SetCachedOwnPublicIpForTesting("203.0.114.55");
            Environment.SetEnvironmentVariable("ABUSEIPDB_API_KEY", "test_dummy_key");

            string attackerIp = "118.25.6.39";
            DatabaseLogger.LogConnection(attackerIp, "RDPClient", "Administrator", "Pass123");

            int callCount = 0;
            var handler = new MockHttpMessageHandler((req) =>
            {
                callCount++;
                Assert.Equal(HttpMethod.Post, req.Method);
                Assert.Equal(AbuseIpDbReporter.ReportEndpointUrl, req.RequestUri?.ToString());
                Assert.Contains("test_dummy_key", req.Headers.GetValues("Key"));

                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent("{\"data\":{\"ipAddress\":\"118.25.6.39\",\"abuseConfidenceScore\":100}}")
                };
            });

            using var client = new HttpClient(handler);

            // First report succeeds and marks DB
            var res1 = await AbuseIpDbReporter.ReportIpAsync(attackerIp, "Administrator", httpClient: client);
            Assert.True(res1.reported);
            Assert.Equal(100, res1.abuseConfidenceScore);
            Assert.Equal(1, callCount);
            Assert.True(DatabaseLogger.HasIpBeenReportedRecently(attackerIp, TimeSpan.FromMinutes(15)));

            // Second report within 15m cooldown is skipped automatically
            var res2 = await AbuseIpDbReporter.ReportIpAsync(attackerIp, "Administrator", httpClient: client);
            Assert.False(res2.reported);
            Assert.Equal(1, callCount);

            // Home IP is never reported
            var resHome = await AbuseIpDbReporter.ReportIpAsync("203.0.114.55", "Administrator", httpClient: client);
            Assert.False(resHome.reported);
            Assert.Equal(1, callCount);
        }

        private sealed class MockHttpMessageHandler : HttpMessageHandler
        {
            private readonly Func<HttpRequestMessage, HttpResponseMessage> _responder;

            public MockHttpMessageHandler(Func<HttpRequestMessage, HttpResponseMessage> responder)
            {
                _responder = responder;
            }

            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                return Task.FromResult(_responder(request));
            }
        }
    }
}
