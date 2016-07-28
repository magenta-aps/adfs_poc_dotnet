using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols.WSTrust;
using Microsoft.IdentityModel.Protocols.WSTrust.Bindings;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.SecurityTokenService;
using System.Security.Claims;
using sm = System.ServiceModel;
using sms = System.ServiceModel.Security;
using System.Xml;
using System.IO;

namespace ADFS
{
    public class TokenHandler
    {
        public static void Handle(System.IdentityModel.Tokens.GenericXmlSecurityToken genericToken, string relyingPartyId, string certSubject)
        {
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
}
