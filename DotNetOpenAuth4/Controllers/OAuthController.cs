using DotNetOpenAuth.OAuth2;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Web;
using System.Web.Mvc;

namespace DotNetOpenAuth4.Controllers
{
    using DotNetOpenAuth.OAuth2;
    using DotNetOpenAuth.Messaging;
    public class OAuthController : Controller
    {
        [HttpPost]
        public ActionResult Token()
        {
            var configuration = new IssuerConfiguration
            {
                EncryptionCertificate = new X509Certificate2(Server.MapPath("~/Certs/localhost.cer")),
                SigningCertificate = new X509Certificate2(Server.MapPath("~/Certs/localhost.pfx"), "a")
            };
            var authServer = new AuthorizationServer(new OAuth2Issuer(configuration));

            return authServer.HandleTokenRequest(Request).AsActionResult();
        }

    }
}
