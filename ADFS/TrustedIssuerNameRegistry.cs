using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

#if Microsoft
using t = System.IdentityModel.Tokens;
#else
using t = Microsoft.IdentityModel.Tokens;
#endif


namespace ADFS
{
    //The token handler calls this to check the token is from a trusted issuer before converting it to a claims principal
    //In this case I authenticate this by checking the certificate name used to sign the token
    public class TrustedIssuerNameRegistry : t.IssuerNameRegistry
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
}
