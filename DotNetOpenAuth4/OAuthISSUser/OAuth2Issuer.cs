using System;
using System.Security.Cryptography;
using DotNetOpenAuth.OAuth2;
using DotNetOpenAuth.Messaging.Bindings;
using DotNetOpenAuth.OAuth2.ChannelElements;
using DotNetOpenAuth.OAuth2.Messages;


namespace DotNetOpenAuth4
{
    public class OAuth2Issuer : IAuthorizationServer
    {
        private readonly IssuerConfiguration _configuration;

        public OAuth2Issuer(IssuerConfiguration configuration)
        {
            if (configuration == null) throw new ArgumentNullException("configuration");
            _configuration = configuration;
        }

        public RSACryptoServiceProvider AccessTokenSigningKey
        {
            get
            {
                return (RSACryptoServiceProvider)_configuration.SigningCertificate.PrivateKey;
            }
        }

        public DotNetOpenAuth.Messaging.Bindings.ICryptoKeyStore CryptoKeyStore
        {
            get { throw new NotImplementedException(); }
        }

        public TimeSpan GetAccessTokenLifetime(IAccessTokenRequest accessTokenRequestMessage)
        {
            return _configuration.TokenLifetime;
        }

        public IClientDescription GetClient(string clientIdentifier)
        {            
            return new ClientDescription(System.Configuration.ConfigurationManager.AppSettings["APISecret"], new Uri("http://localhost/"), ClientType.Confidential);
        }

        public RSACryptoServiceProvider GetResourceServerEncryptionKey(IAccessTokenRequest accessTokenRequestMessage)
        {
            return (RSACryptoServiceProvider)_configuration.EncryptionCertificate.PublicKey.Key;

        }

        public bool IsAuthorizationValid(IAuthorizationDescription authorization)
        {

            //claims added to the token
            authorization.Scope.Add("adminstrator");
            authorization.Scope.Add("poweruser");

            return true;
        }

        public bool IsResourceOwnerCredentialValid(string userName, string password)
        {
            return true;
        }

        public INonceStore VerificationCodeNonceStore
        {
            get
            {
                throw new NotImplementedException();
            }
        }
    }
}