using System;
using System.Security.Cryptography.X509Certificates;

namespace DotNetOpenAuth4
{
public class IssuerConfiguration
{
    public IssuerConfiguration()
    {
        TokenLifetime = TimeSpan.FromMinutes(5);
    }
    public X509Certificate2 SigningCertificate { get; set; }
    public X509Certificate2 EncryptionCertificate { get; set; }

    public TimeSpan TokenLifetime { get; set; }
}
}