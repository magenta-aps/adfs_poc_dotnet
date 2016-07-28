using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace ADFS
{
    public class Base64TokenDecoder
    {
        public static void DecodeToken()
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
