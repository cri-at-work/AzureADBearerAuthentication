using System;
using System.Collections.Generic;
using System.IdentityModel.Metadata;
using System.IdentityModel.Tokens;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel.Security;
using System.Xml;

namespace ServiceStack.Authentication.Aad
{
    internal class IssuerSigningKeys
    {
        /// <summary>
        /// The token issuer.
        /// </summary>
        public string Issuer { get; set; }

        /// <summary>
        /// Signing tokens.
        /// </summary>
        public IEnumerable<X509SecurityToken> Tokens { get; set; }
    }

	internal class WsFedMetadataRetriever
	{
		private static readonly XmlReaderSettings SafeSettings = new XmlReaderSettings { XmlResolver = null, DtdProcessing = DtdProcessing.Prohibit, ValidationType = ValidationType.None };

		const string Exception_MissingDescriptor = "No SecurityTokenServiceType descriptor in metadata.";

        public static IssuerSigningKeys GetSigningKeys(string metadataEndpoint, TimeSpan backchannelTimeout, HttpMessageHandler backchannelHttpHandler)
        {
            string issuer = string.Empty;
            var tokens = new List<X509SecurityToken>();

            using (var metadataRequest = new HttpClient(backchannelHttpHandler, false))
            {
                metadataRequest.Timeout = backchannelTimeout;
                using (HttpResponseMessage metadataResponse = metadataRequest.GetAsync(metadataEndpoint).Result)
                {
                    metadataResponse.EnsureSuccessStatusCode();
                    Stream metadataStream = metadataResponse.Content.ReadAsStreamAsync().Result;
                    using (XmlReader metaDataReader = XmlReader.Create(metadataStream, SafeSettings))
                    {
                        var serializer = new MetadataSerializer { CertificateValidationMode = X509CertificateValidationMode.None };

                        MetadataBase metadata = serializer.ReadMetadata(metaDataReader);
                        var entityDescriptor = (EntityDescriptor)metadata;

                        if (!string.IsNullOrWhiteSpace(entityDescriptor.EntityId.Id))
                        {
                            issuer = entityDescriptor.EntityId.Id;
                        }

                        SecurityTokenServiceDescriptor stsd = entityDescriptor.RoleDescriptors.OfType<SecurityTokenServiceDescriptor>().First();
                        if (stsd == null)
                        {
                            throw new InvalidOperationException(Exception_MissingDescriptor);
                        }

                        IEnumerable<X509RawDataKeyIdentifierClause> x509DataClauses =
                            stsd.Keys.Where(key => key.KeyInfo != null
                                && (key.Use == KeyType.Signing || key.Use == KeyType.Unspecified))
                                    .Select(key => key.KeyInfo.OfType<X509RawDataKeyIdentifierClause>().First());
                        tokens.AddRange(x509DataClauses.Select(token => new X509SecurityToken(new X509Certificate2(token.GetX509RawData()))));
                    }
                }
            }

            return new IssuerSigningKeys { Issuer = issuer, Tokens = tokens };
        }
    }
	
}
