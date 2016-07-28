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

namespace ConsoleApplication1
{
    class Program
    {
        static void Main()
        {
            Authenticate();
            //DecodeToken();
        }

        static void Authenticate()
        {
            //string relyingPartyId = "https://adfsserver.security.net/MyApp"; //ID of the relying party in AD FS
            string relyingPartyId = "https://fs.magenta.dk"; // Relying party trust identifier

            string adfsEndpoint = "https://adroot2008.win2008.magenta.dk/adfs/services/trust/13/windowsmixed";

            const string certSubject = "CN=adfsserver.security.net";

            //Setup the connection to ADFS
            var factory = new WSTrustChannelFactory(new WindowsWSTrustBinding(sm.SecurityMode.TransportWithMessageCredential), new sm.EndpointAddress(adfsEndpoint))
            {
                TrustVersion = sms.TrustVersion.WSTrust13
            };

            factory.Credentials.Windows.ClientCredential.Domain = "";
            factory.Credentials.Windows.ClientCredential.UserName = "";
            factory.Credentials.Windows.ClientCredential.Password = "";
            factory.Credentials.Windows.AllowedImpersonationLevel = System.Security.Principal.TokenImpersonationLevel.Impersonation;


            //Setup the request object 
            var rst = new RequestSecurityToken
            {
                RequestType = RequestTypes.Issue,
                KeyType = KeyTypes.Bearer,
                AppliesTo = new sm.EndpointAddress(relyingPartyId),
                TokenType = "urn:oasis:names:tc:SAML:2.0:assertion",

            };


            System.Net.ServicePointManager.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => true;


            //Open a connection to ADFS and get a token for the logged in user
            var channel = factory.CreateChannel();

            var genericToken = channel.Issue(rst) as System.IdentityModel.Tokens.GenericXmlSecurityToken;


            if (genericToken != null)
            {
                XmlDocument doc = new XmlDocument();
                doc.LoadXml(genericToken.TokenXml.OuterXml);
                doc.Save(@"..\..\Token-ADFS2.xml");

                return;
                //Setup the handlers needed to convert the generic token to a SAML Token
                var tokenHandlers = new SecurityTokenHandlerCollection(new SecurityTokenHandler[] { new Microsoft.IdentityModel.Tokens.Saml2.Saml2SecurityTokenHandler() });
                tokenHandlers.Configuration.AudienceRestriction = new AudienceRestriction();
                tokenHandlers.Configuration.AudienceRestriction.AllowedAudienceUris.Add(new Uri(relyingPartyId));

                var trusted = new TrustedIssuerNameRegistry(certSubject);
                tokenHandlers.Configuration.IssuerNameRegistry = trusted;

                //convert the generic security token to a saml token
                var samlToken = tokenHandlers.ReadToken(new XmlTextReader(new StringReader(genericToken.TokenXml.OuterXml)));
                var saml2Token = samlToken as Microsoft.IdentityModel.Tokens.Saml2.Saml2SecurityToken;

                //convert the saml token to a claims principal
                var claimsPrincipal = new ClaimsPrincipal(tokenHandlers.ValidateToken(samlToken).First());

                //Display token information
                Console.WriteLine("Name : " + claimsPrincipal.Identity.Name);
                Console.WriteLine("Auth Type : " + claimsPrincipal.Identity.AuthenticationType);
                Console.WriteLine("Is Authed : " + claimsPrincipal.Identity.IsAuthenticated);
                foreach (var c in claimsPrincipal.Claims)
                    Console.WriteLine(c.Type + " / " + c.Value);
                Console.ReadLine();
            }
        }

        //The token handler calls this to check the token is from a trusted issuer before converting it to a claims principal
        //In this case I authenticate this by checking the certificate name used to sign the token
        public class TrustedIssuerNameRegistry : IssuerNameRegistry
        {
            private string _certSubject;

            public TrustedIssuerNameRegistry(string certSubject)
            {
                _certSubject = certSubject;
            }

            public override string GetIssuerName(System.IdentityModel.Tokens.SecurityToken securityToken)
            {
                var x509Token = securityToken as System.IdentityModel.Tokens.X509SecurityToken;
                if (x509Token != null && x509Token.Certificate.SubjectName.Name != null && x509Token.Certificate.SubjectName.Name.Contains(_certSubject))
                    return x509Token.Certificate.SubjectName.Name;
                throw new System.IdentityModel.Tokens.SecurityTokenException("Untrusted issuer.");
            }
        }

        static void DecodeToken()
        {
            var txt = File.ReadAllText(@"..\..\Token.txt");
            txt = txt.Substring(txt.IndexOf(" ") + 1);
            var bytes = Convert.FromBase64String(txt);
            var str = new System.IO.Compression.GZipStream(new MemoryStream(bytes), System.IO.Compression.CompressionMode.Decompress);


            XmlDocument doc = new XmlDocument();

            doc.NameTable.Add("urn:oasis:names:tc:SAML:2.0:assertion");

            doc.Load(str);
            var targetFile = @"..\..\Token.xml";

            var e = doc.DocumentElement;
            e.SetAttribute("xmlns", "urn:oasis:names:tc:SAML:2.0:assertion");

            Action<XmlElement> changePrefix = null;

            changePrefix = new Action<XmlElement>((XmlElement elm) =>
               {
                   if (elm.Prefix == "saml2")
                   {
                       elm.Prefix = "";
                   }
                   foreach (var c in elm.ChildNodes.OfType<XmlElement>())
                       changePrefix(c);
               });

            changePrefix(e);

            doc.Save(targetFile);
        }

    }
}