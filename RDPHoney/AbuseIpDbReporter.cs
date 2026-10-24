using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;

namespace RDPHoney
{
    // Purpose: Automatically reports banned RDPClient attacker IPs to AbuseIPDB APIv2 (/api/v2/report)
    // and supports checking IP reputation (/api/v2/check).
    // Includes strict safeguards to never report loopback, private, reserved, or the host's own home/public IP.
    //
    // Dmitry Porotnikov

    public static class AbuseIpDbReporter
    {
        public const string ReportEndpointUrl = "https://api.abuseipdb.com/api/v2/report";
        public const string CheckEndpointUrl = "https://api.abuseipdb.com/api/v2/check";

        private static readonly HttpClient SharedHttpClient = new()
        {
            Timeout = TimeSpan.FromSeconds(15)
        };

        private static string? _cachedOwnPublicIp;
        private static bool _ownPublicIpResolved;
        private static readonly object _ownIpLock = new();

        public static string? GetApiKey()
        {
            var key = Environment.GetEnvironmentVariable("ABUSEIPDB_API_KEY");
            return string.IsNullOrWhiteSpace(key) ? null : key.Trim();
        }

        public static bool IsEnabled()
        {
            if (string.IsNullOrWhiteSpace(GetApiKey()))
            {
                return false;
            }

            var enabledEnv = Environment.GetEnvironmentVariable("ABUSEIPDB_ENABLED")
                             ?? Environment.GetEnvironmentVariable("AUTO_REPORT_ABUSEIPDB");

            if (!string.IsNullOrWhiteSpace(enabledEnv) &&
                (string.Equals(enabledEnv.Trim(), "false", StringComparison.OrdinalIgnoreCase) ||
                 string.Equals(enabledEnv.Trim(), "0", StringComparison.OrdinalIgnoreCase)))
            {
                return false;
            }

            return true;
        }

        public static string GetCategories()
        {
            var cats = Environment.GetEnvironmentVariable("ABUSEIPDB_CATEGORIES");
            if (!string.IsNullOrWhiteSpace(cats))
            {
                return cats.Trim();
            }

            // Default AbuseIPDB categories for RDP Honeypot: 18 (Brute-Force), 15 (Hacking)
            return "18,15";
        }

        public static HashSet<string> GetExcludedIps()
        {
            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var env = Environment.GetEnvironmentVariable("ABUSEIPDB_EXCLUDED_IPS")
                      ?? Environment.GetEnvironmentVariable("HOME_IP");

            if (!string.IsNullOrWhiteSpace(env))
            {
                foreach (var part in env.Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    if (IPAddress.TryParse(part.Trim(), out var parsed))
                    {
                        set.Add(NormalizeIp(parsed).ToString());
                    }
                }
            }

            string? ownIp = GetOwnPublicIp();
            if (!string.IsNullOrWhiteSpace(ownIp))
            {
                set.Add(ownIp);
            }

            return set;
        }

        public static string? GetOwnPublicIp()
        {
            if (_ownPublicIpResolved)
            {
                return _cachedOwnPublicIp;
            }

            lock (_ownIpLock)
            {
                if (_ownPublicIpResolved)
                {
                    return _cachedOwnPublicIp;
                }

                try
                {
                    using var cts = new System.Threading.CancellationTokenSource(TimeSpan.FromSeconds(4));
                    var response = SharedHttpClient.GetStringAsync("https://api.ipify.org", cts.Token).GetAwaiter().GetResult();
                    if (!string.IsNullOrWhiteSpace(response) && IPAddress.TryParse(response.Trim(), out var ip))
                    {
                        _cachedOwnPublicIp = NormalizeIp(ip).ToString();
                    }
                }
                catch
                {
                    // Ignore failure if offline or blocked
                }
                finally
                {
                    _ownPublicIpResolved = true;
                }

                return _cachedOwnPublicIp;
            }
        }

        public static void SetCachedOwnPublicIpForTesting(string? ip)
        {
            lock (_ownIpLock)
            {
                _cachedOwnPublicIp = ip;
                _ownPublicIpResolved = true;
            }
        }

        public static IPAddress NormalizeIp(IPAddress ip)
        {
            return ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip;
        }

        public static bool IsReportablePublicIp(string ipAddress)
        {
            if (string.IsNullOrWhiteSpace(ipAddress) || !IPAddress.TryParse(ipAddress.Trim(), out var rawIp))
            {
                return false;
            }

            var ip = NormalizeIp(rawIp);

            if (IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.None) || ip.Equals(IPAddress.IPv6Any) || ip.Equals(IPAddress.IPv6None))
            {
                return false;
            }

            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                byte[] b = ip.GetAddressBytes();

                // 0.0.0.0/8 (Current network)
                if (b[0] == 0) return false;
                // 10.0.0.0/8 (Private network)
                if (b[0] == 10) return false;
                // 100.64.0.0/10 (Carrier-grade NAT)
                if (b[0] == 100 && (b[1] & 0xC0) == 64) return false;
                // 127.0.0.0/8 (Loopback)
                if (b[0] == 127) return false;
                // 169.254.0.0/16 (Link-local)
                if (b[0] == 169 && b[1] == 254) return false;
                // 172.16.0.0/12 (Private network / Docker bridges)
                if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return false;
                // 192.0.0.0/24 (IETF Protocol Assignments)
                if (b[0] == 192 && b[1] == 0 && b[2] == 0) return false;
                // 192.0.2.0/24 (TEST-NET-1)
                if (b[0] == 192 && b[1] == 0 && b[2] == 2) return false;
                // 192.168.0.0/16 (Private network)
                if (b[0] == 192 && b[1] == 168) return false;
                // 198.18.0.0/15 (Benchmarking)
                if (b[0] == 198 && (b[1] == 18 || b[1] == 19)) return false;
                // 198.51.100.0/24 (TEST-NET-2)
                if (b[0] == 198 && b[1] == 51 && b[2] == 100) return false;
                // 203.0.113.0/24 (TEST-NET-3)
                if (b[0] == 203 && b[1] == 0 && b[2] == 113) return false;
                // 224.0.0.0/4 (Multicast) & 240.0.0.0/4 (Reserved/Broadcast)
                if (b[0] >= 224) return false;
            }
            else if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            {
                if (ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || ip.IsIPv6Multicast)
                {
                    return false;
                }

                byte[] b = ip.GetAddressBytes();
                // fc00::/7 (Unique Local Address)
                if ((b[0] & 0xFE) == 0xFC) return false;
                // 2001:db8::/32 (Documentation)
                if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0D && b[3] == 0xB8) return false;
            }

            var excluded = GetExcludedIps();
            if (excluded.Contains(ip.ToString()))
            {
                return false;
            }

            return true;
        }

        public static string BuildReportComment(string? username, int port = 3389)
        {
            // AbuseIPDB requires stripping PII/passwords from public comments
            if (!string.IsNullOrWhiteSpace(username))
            {
                string safeUser = username.Length > 32 ? username[..32] : username;
                return $"RDP Honeypot: Unauthorized RDP login attempt on port {port} (user: {safeUser}). Client banned.";
            }

            return $"RDP Honeypot: Unauthorized RDP connection and login attempt on port {port}. Client banned.";
        }

        public static void ReportRdpClientInBackground(string ipAddress, string? username = null)
        {
            if (!IsEnabled())
            {
                return;
            }

            _ = Task.Run(async () =>
            {
                try
                {
                    await ReportIpAsync(ipAddress, username);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[AbuseIPDB] Error reporting {ipAddress}: {ex.Message}");
                }
            });
        }

        public static async Task<(bool reported, int? abuseConfidenceScore, string detail)> ReportIpAsync(
            string ipAddress,
            string? username = null,
            string? customComment = null,
            HttpClient? httpClient = null,
            bool allowTestLoopback = false)
        {
            string? apiKey = GetApiKey();
            if (string.IsNullOrWhiteSpace(apiKey))
            {
                return (false, null, "ABUSEIPDB_API_KEY is not configured.");
            }

            if (!IsEnabled())
            {
                return (false, null, "AbuseIPDB reporting is disabled.");
            }

            string normalizedIp = IPAddress.TryParse(ipAddress.Trim(), out var parsedIp)
                ? NormalizeIp(parsedIp).ToString()
                : ipAddress.Trim();

            bool isOfficialTestIp = allowTestLoopback && (normalizedIp == "127.0.0.1" || normalizedIp == "127.0.0.2");
            if (!isOfficialTestIp && !IsReportablePublicIp(normalizedIp))
            {
                Console.WriteLine($"[AbuseIPDB] Skipping report for excluded/private/home IP: {normalizedIp}");
                return (false, null, $"IP {normalizedIp} is private, reserved, or excluded (home IP).");
            }

            if (!isOfficialTestIp && DatabaseLogger.HasIpBeenReportedRecently(normalizedIp, TimeSpan.FromMinutes(15)))
            {
                Console.WriteLine($"[AbuseIPDB] Skipping duplicate report for {normalizedIp} (already reported within 15m cooldown).");
                return (false, null, $"IP {normalizedIp} was already reported recently.");
            }

            string categories = GetCategories();
            string comment = string.IsNullOrWhiteSpace(customComment)
                ? BuildReportComment(username, EnhancedRDPServerHoneypot.ResolvePort())
                : customComment;
            string timestamp = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:sszzz");

            var client = httpClient ?? SharedHttpClient;
            using var request = new HttpRequestMessage(HttpMethod.Post, ReportEndpointUrl);
            request.Headers.Add("Key", apiKey);
            request.Headers.Add("Accept", "application/json");
            request.Content = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("ip", normalizedIp),
                new KeyValuePair<string, string>("categories", categories),
                new KeyValuePair<string, string>("comment", comment),
                new KeyValuePair<string, string>("timestamp", timestamp)
            });

            using var response = await client.SendAsync(request);
            string body = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                Console.WriteLine($"[AbuseIPDB] Report API returned HTTP {(int)response.StatusCode} for {normalizedIp}: {body}");
                return (false, null, body);
            }

            int? score = null;
            try
            {
                using var doc = JsonDocument.Parse(body);
                if (doc.RootElement.TryGetProperty("data", out var dataEl) &&
                    dataEl.TryGetProperty("abuseConfidenceScore", out var scoreEl) &&
                    scoreEl.TryGetInt32(out int parsedScore))
                {
                    score = parsedScore;
                }
            }
            catch
            {
                // Ignore JSON parse issues if format differs
            }

            if (!isOfficialTestIp)
            {
                try
                {
                    DatabaseLogger.MarkIpAsReported(normalizedIp, score);
                }
                catch
                {
                    // Best-effort database status update
                }
            }

            Console.WriteLine($"[AbuseIPDB] Successfully reported banned RDPClient {normalizedIp} (AbuseConfidenceScore: {score?.ToString() ?? "N/A"}%).");
            return (true, score, body);
        }

        public static async Task<(bool success, int abuseConfidenceScore, int totalReports, string? countryCode, string? isp, bool isWhitelisted, string rawJson)> CheckIpAsync(
            string ipAddress,
            int maxAgeInDays = 90,
            HttpClient? httpClient = null)
        {
            string? apiKey = GetApiKey();
            if (string.IsNullOrWhiteSpace(apiKey))
            {
                return (false, 0, 0, null, null, false, "ABUSEIPDB_API_KEY is not configured.");
            }

            string url = $"{CheckEndpointUrl}?ipAddress={Uri.EscapeDataString(ipAddress.Trim())}&maxAgeInDays={maxAgeInDays}&verbose";
            var client = httpClient ?? SharedHttpClient;

            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.Add("Key", apiKey);
            request.Headers.Add("Accept", "application/json");

            using var response = await client.SendAsync(request);
            string body = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                return (false, 0, 0, null, null, false, body);
            }

            int score = 0;
            int totalReports = 0;
            string? countryCode = null;
            string? isp = null;
            bool isWhitelisted = false;

            try
            {
                using var doc = JsonDocument.Parse(body);
                if (doc.RootElement.TryGetProperty("data", out var data))
                {
                    if (data.TryGetProperty("abuseConfidenceScore", out var s) && s.TryGetInt32(out int sv)) score = sv;
                    if (data.TryGetProperty("totalReports", out var tr) && tr.TryGetInt32(out int trv)) totalReports = trv;
                    if (data.TryGetProperty("countryCode", out var cc) && cc.ValueKind == JsonValueKind.String) countryCode = cc.GetString();
                    if (data.TryGetProperty("isp", out var ispEl) && ispEl.ValueKind == JsonValueKind.String) isp = ispEl.GetString();
                    if (data.TryGetProperty("isWhitelisted", out var wl) && (wl.ValueKind == JsonValueKind.True || wl.ValueKind == JsonValueKind.False))
                    {
                        isWhitelisted = wl.GetBoolean();
                    }
                }
            }
            catch
            {
                return (false, 0, 0, null, null, false, body);
            }

            return (true, score, totalReports, countryCode, isp, isWhitelisted, body);
        }
    }
}
