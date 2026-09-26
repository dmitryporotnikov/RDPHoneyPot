using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace RDPHoney
{
    // Purpose: Generates and manages an in-memory self-signed X.509 TLS certificate for RDP TLS negotiation.
    //
    // Dmitry Porotnikov

    public static class TlsCertificateManager
    {
        private static readonly Lazy<X509Certificate2> _serverCert = new(GenerateSelfSignedCertificate);

        public static X509Certificate2 ServerCertificate => _serverCert.Value;

        private static X509Certificate2 GenerateSelfSignedCertificate()
        {
            using var rsa = RSA.Create(2048);
            var req = new CertificateRequest("CN=WIN-SRV-2019", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            var sanBuilder = new SubjectAlternativeNameBuilder();
            sanBuilder.AddDnsName("WIN-SRV-2019");
            sanBuilder.AddDnsName("localhost");
            sanBuilder.AddIpAddress(System.Net.IPAddress.Loopback);
            sanBuilder.AddIpAddress(System.Net.IPAddress.IPv6Loopback);
            req.CertificateExtensions.Add(sanBuilder.Build());

            req.CertificateExtensions.Add(
                new X509EnhancedKeyUsageExtension(
                    new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));

            var cert = req.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddDays(-1),
                DateTimeOffset.UtcNow.AddYears(5));

            // Export to PKCS#12 and re-import to ensure private key is retained across all OS platforms
            return X509CertificateLoader.LoadPkcs12(cert.Export(X509ContentType.Pfx), null, X509KeyStorageFlags.Exportable);
        }
    }
}
