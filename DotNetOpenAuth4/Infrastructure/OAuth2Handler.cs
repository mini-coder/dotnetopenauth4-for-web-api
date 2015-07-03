using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using DotNetOpenAuth.OAuth2;
using Microsoft.IdentityModel;



namespace DotNetOpenAuth4.Infrastructure
{ 
    public class OAuth2Handler : DelegatingHandler
    {
        private readonly ResourceServerConfiguration _configuration;

        public OAuth2Handler(ResourceServerConfiguration configuration)
        {
            if (configuration == null) throw new ArgumentNullException("configuration");
            _configuration = configuration;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            HttpContextBase httpContext;
            string userName;
            HashSet<string> scope;

            if (!request.TryGetHttpContext(out httpContext))
                throw new InvalidOperationException("HttpContext must not be null.");

            var resourceServer = new ResourceServer(new StandardAccessTokenAnalyzer(
                                                        (RSACryptoServiceProvider)_configuration.IssuerSigningCertificate.PublicKey.Key,
                                                        (RSACryptoServiceProvider)_configuration.EncryptionVerificationCertificate.PrivateKey));

            var error = resourceServer.VerifyAccess(httpContext.Request, out userName, out scope);


            if (error != null)
                return Task<HttpResponseMessage>.Factory.StartNew(error.ToHttpResponseMessage);

            Microsoft.IdentityModel.Claims.ClaimsIdentity identity = new Microsoft.IdentityModel.Claims.ClaimsIdentity(scope.Select(s => new Microsoft.IdentityModel.Claims.Claim(s, s)));
            if (!string.IsNullOrEmpty(userName))
                identity.Claims.Add(new Microsoft.IdentityModel.Claims.Claim(Microsoft.IdentityModel.Claims.ClaimTypes.Name, userName));
            
            httpContext.User = Microsoft.IdentityModel.Claims.ClaimsPrincipal.CreateFromIdentity(identity);
            Thread.CurrentPrincipal = httpContext.User;

            return base.SendAsync(request, cancellationToken);
        }

    }
}