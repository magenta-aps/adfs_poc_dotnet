using System;
using System.IO;
using Microsoft.IdentityModel.Protocols.WSTrust;
using Microsoft.IdentityModel.Protocols.WSTrust.Bindings;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.SecurityTokenService;
using System.Linq;
using System.Security.Claims;
using sm = System.ServiceModel;
using sms = System.ServiceModel.Security;
using System.Xml;
using System.Net;

namespace ADFS
{
    class Program
    {
        static void Main()
        {
            Authenticate();
            //Base64TokenDecoder.DecodeToken();
        }

        static void Authenticate()
        {
            System.Net.ServicePointManager.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => true;

            const string relyingPartyId = "https://fs.magenta.dk"; // Relying party trust identifier
            const string adfsEndpoint = "https://adroot2008.win2008.magenta.dk/adfs/services/trust/13/windowsmixed";
            const string certSubject = "CN=adfsserver.security.net";

            //Setup the connection to ADFS
            var factory = new WSTrustChannelFactory(new WindowsWSTrustBinding(sm.SecurityMode.TransportWithMessageCredential), new sm.EndpointAddress(adfsEndpoint))
            {
                TrustVersion = sms.TrustVersion.WSTrust13
            };

            factory.Credentials.Windows.ClientCredential = new ObjectFiller().Create<NetworkCredential>(@"..\..\ADFSLogin.txt");

            factory.Credentials.Windows.AllowedImpersonationLevel = System.Security.Principal.TokenImpersonationLevel.Impersonation;
            
            //Setup the request object 
            var rst = new RequestSecurityToken
            {
                RequestType = RequestTypes.Issue,
                KeyType = KeyTypes.Bearer,
                AppliesTo = new sm.EndpointAddress(relyingPartyId),
                TokenType = "urn:oasis:names:tc:SAML:2.0:assertion",
            };

            //Open a connection to ADFS and get a token for the logged in user
            var channel = factory.CreateChannel();

            var genericToken = channel.Issue(rst) as System.IdentityModel.Tokens.GenericXmlSecurityToken;
            
            if (genericToken != null)
            {
                XmlDocument doc = new XmlDocument();
                doc.LoadXml(genericToken.TokenXml.OuterXml);
                doc.Save(@"..\..\Token-ADFS2.xml");

                // Extra handling - not used ATM
                //TokenHandler.Handle(genericToken, relyingPartyId, certSubject);
            }
        }
        
    }
}