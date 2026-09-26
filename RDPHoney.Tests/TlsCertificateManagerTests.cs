using System.Security.Cryptography.X509Certificates;
using RDPHoney;
using Xunit;

namespace RDPHoney.Tests
{
    public class TlsCertificateManagerTests
    {
        [Fact]
        public void ServerCertificate_HasPrivateKeyAndValidSubject()
        {
            var cert = TlsCertificateManager.ServerCertificate;
            Assert.NotNull(cert);
            Assert.True(cert.HasPrivateKey);
            Assert.Contains("WIN-SRV", cert.Subject);
        }
    }
}
