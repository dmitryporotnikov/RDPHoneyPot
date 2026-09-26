using System;
using System.IO;
using RDPHoney;
using Xunit;

namespace RDPHoney.Tests
{
    public class RdpScreenRendererTests : IDisposable
    {
        private readonly string _tempJpgPath;

        public RdpScreenRendererTests()
        {
            _tempJpgPath = Path.Combine(Path.GetTempPath(), $"test_desktop_{Guid.NewGuid():N}.jpg");
            Environment.SetEnvironmentVariable("STATIC_JPG_PATH", _tempJpgPath);
        }

        public void Dispose()
        {
            try
            {
                Environment.SetEnvironmentVariable("STATIC_JPG_PATH", null);
                if (File.Exists(_tempJpgPath))
                {
                    File.Delete(_tempJpgPath);
                }
            }
            catch { }
        }

        [Fact]
        public void EnsureDefaultStaticJpgExists_GeneratesValidJpgFile()
        {
            RdpScreenRenderer.EnsureDefaultStaticJpgExists();

            Assert.True(File.Exists(_tempJpgPath));
            var fileInfo = new FileInfo(_tempJpgPath);
            Assert.True(fileInfo.Length > 1000); // JPEG header and compressed pixels
        }

        [Fact]
        public void LoadStaticJpgRgb_LoadsAndMatchesDimensions()
        {
            RdpScreenRenderer.EnsureDefaultStaticJpgExists();

            int targetW = 800;
            int targetH = 600;
            byte[] rgb = RdpScreenRenderer.LoadStaticJpgRgb(targetW, targetH);

            Assert.NotNull(rgb);
            Assert.Equal(targetW * targetH * 3, rgb.Length);
        }

        [Fact]
        public void GenerateLoginScreenRgb_CreatesValidRgbBuffer()
        {
            int w = 1024;
            int h = 768;
            byte[] rgb = RdpScreenRenderer.GenerateLoginScreenRgb(w, h, "admin", "secret123", isPasswordActive: true);

            Assert.NotNull(rgb);
            Assert.Equal(w * h * 3, rgb.Length);
        }

        [Fact]
        public void SendBitmapUpdate_StreamsValidFastPathPackets()
        {
            using var ms = new MemoryStream();
            int w = 800;
            int h = 60; // 6 strips of 10 rows
            byte[] rgb = new byte[w * h * 3];

            RdpScreenRenderer.SendBitmapUpdate(ms, rgb, w, h);

            byte[] output = ms.ToArray();
            Assert.True(output.Length > 0);
            // Verify first byte is Fast-Path output header (0x00)
            Assert.Equal(0x00, output[0]);
        }
    }
}
