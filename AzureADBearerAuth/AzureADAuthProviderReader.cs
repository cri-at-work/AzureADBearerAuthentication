using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Cryptography;
using ServiceStack.Auth;
using ServiceStack.Configuration;
using ServiceStack.Host;
using ServiceStack.Text;
using ServiceStack.Web;

namespace ServiceStack.Authentication.Aad
{
	/// <summary>
	/// Enable access to protected Services using JWT Tokens
	/// </summary>
	public class AzureADAuthProviderReader : AuthProvider, IAuthWithRequest, IAuthPlugin
	{
		public const string Name = "aadr";
		public static string Realm = "https://login.microsoftonline.com/";

		internal const string FederationMetadataUrlTemplate =
			"https://login.windows.net/{0}/federationmetadata/2007-06/federationmetadata.xml";

		private JwtAuthProviderReader _jwtAuthProviderReader;

		/// <summary>
		/// 
		/// </summary>
		public bool RequireSecureConnection { get; set; }

		/// <summary>
		/// The Audience to embed in the token. (default null)
		/// </summary>
		public string Audience { get; set; }

		/// <summary>
		/// The Audience to embed in the token. (default null)
		/// </summary>
		public string Tenant { get; set; }


		/// <summary>
		/// How long should JWT Tokens be valid for. (default 14 days)
		/// </summary>
		public TimeSpan ExpireTokensIn { get; set; }

		/// <summary>
		/// Convenient overload to initialize ExpireTokensIn with an Integer
		/// </summary>
		public int ExpireTokensInDays
		{
			set
			{
				if (value > 0)
					ExpireTokensIn = TimeSpan.FromDays(value);
			}
		}

		/// <summary>
		/// Whether to invalidate all JWT Tokens issued before a specified date.
		/// </summary>
		public DateTime? InvalidateTokensIssuedBefore { get; set; }

		/// <summary>
		/// Which Hash Algorithm should be used to sign the JWT Token. (default HS256)
		/// </summary>
		private string HashAlgorithm { get; set; }

		private IList<RSAParameters> _publicKeys { get; set; }

		internal static List<RSAParameters> RetrievePublicKeys(string tenant)
		{
			// TODO: retrieve public keys every N hours
			var federationMetadataUrl = FederationMetadataUrlTemplate.Fmt(tenant);
			var issuerSigningKeys =
				WsFedMetadataRetriever.GetSigningKeys(federationMetadataUrl, TimeSpan.FromMinutes(1), new WebRequestHandler());

			var publicKeys = new List<RSAParameters>();
			foreach (var token in issuerSigningKeys.Tokens)
			{
				var provider = (RSACryptoServiceProvider)token.Certificate.PublicKey.Key;
				publicKeys.Add(provider.ExportParameters(false));
			}

			if (publicKeys.Count == 0)
			{
				throw new TokenException("No public key found at " + federationMetadataUrl);
			}

			return publicKeys;
		}

		public AzureADAuthProviderReader()
		{
			Init();
		}

		public AzureADAuthProviderReader(IAppSettings appSettings)
			: base(appSettings, Realm, Name)
		{
			Init(appSettings);
		}

		public virtual void Init(IAppSettings appSettings = null)
		{
			RequireSecureConnection = true;
			HashAlgorithm = "RS256";
			ExpireTokensIn = TimeSpan.FromDays(14);

			if (appSettings != null)
			{
				RequireSecureConnection = appSettings.Get("aadr.RequireSecureConnection", RequireSecureConnection);

				//Issuer = appSettings.GetString("jwt.Issuer");
				Audience = appSettings.GetString("aadr.Audience");
				Tenant = appSettings.GetString("aadr.Tenant");
				//KeyId = appSettings.GetString("jwt.KeyId");

				//var hashAlg = appSettings.GetString("aadr.HashAlgorithm");
				//if (!string.IsNullOrEmpty(hashAlg))
				//	HashAlgorithm = hashAlg;

				//RequireHashAlgorithm = appSettings.Get("jwt.RequireHashAlgorithm", RequireSecureConnection);

				//PrivateKeyXml = appSettings.GetString("jwt.PrivateKeyXml");

				//PublicKeyXml = appSettings.GetString("jwt.PublicKeyXml");

				//var base64 = appSettings.GetString("jwt.AuthKeyBase64");
				//if (base64 != null)
				//	AuthKeyBase64 = base64;

				var dateStr = appSettings.GetString("aadr.InvalidateTokensIssuedBefore");
				if (!string.IsNullOrEmpty(dateStr))
					InvalidateTokensIssuedBefore = dateStr.FromJsv<DateTime>();

				ExpireTokensIn = appSettings.Get("aadr.ExpireTokensIn", ExpireTokensIn);

				var intStr = appSettings.GetString("aadr.ExpireTokensInDays");
				if (intStr != null)
					ExpireTokensInDays = int.Parse(intStr);
			}

			_jwtAuthProviderReader = new JwtAuthProviderReader();
			_jwtAuthProviderReader.RequireSecureConnection = RequireSecureConnection;
			//_jwtAuthProviderReader.Issuer = "ssjwt";
			_jwtAuthProviderReader.ExpireTokensIn = ExpireTokensIn;
			_jwtAuthProviderReader.InvalidateTokensIssuedBefore = InvalidateTokensIssuedBefore;

			_publicKeys = RetrievePublicKeys(Tenant);
		}


		public override bool IsAuthorized(IAuthSession session, IAuthTokens tokens, Authenticate request = null)
		{
			return _jwtAuthProviderReader.IsAuthorized(session, tokens, request);
		}

		public override object Authenticate(IServiceBase authService, IAuthSession session, Authenticate request)
		{
			throw new NotImplementedException("JWT Authenticate() should not be called directly");
		}

		public void PreAuthenticate(IRequest req, IResponse res)
		{
			if (req.OperationName != null && JwtAuthProviderReader.IgnoreForOperationTypes.Contains(req.OperationName))
				return;

			var bearerToken = req.GetBearerToken()
					?? req.GetCookieValue(Keywords.TokenCookie);

			if (bearerToken != null)
			{
				var parts = bearerToken.Split('.');
				if (parts.Length != 3)
				{
					throw new TokenException("Azure AD jwt token should have 3 parts.");
				}


				if (RequireSecureConnection && !req.IsSecureConnection)
					throw HttpError.Forbidden(ErrorMessages.JwtRequiresSecureConnection);

				var header = parts[0];
				var payload = parts[1];
				var signatureBytes = parts[2].FromBase64UrlSafe();

				var headerJson = header.FromBase64UrlSafe().FromUtf8Bytes();
				var payloadBytes = payload.FromBase64UrlSafe();

				var headerData = headerJson.FromJson<Dictionary<string, string>>();

				var bytesToSign = string.Concat(header, ".", payload).ToUtf8Bytes();

				var algorithm = headerData["alg"];

				//Potential Security Risk for relying on user-specified algorithm: https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries/
				//if (RequireHashAlgorithm && algorithm != HashAlgorithm)
				//	throw new NotSupportedException("Invalid algoritm '{0}', expected '{1}'".Fmt(algorithm, HashAlgorithm));

				if (!VerifyPayload(algorithm, bytesToSign, signatureBytes))
					return;

				var payloadJson = payloadBytes.FromUtf8Bytes();
				var jwtPayload = JsonObject.Parse(payloadJson);

				var session = CreateSessionFromPayload(req, jwtPayload);
				req.Items[Keywords.Session] = session;
			}
		}


		public bool VerifyPayload(string algorithm, byte[] bytesToSign, byte[] sentSignatureBytes)
		{
			foreach (var publicKey in _publicKeys)
			{
				var verified = JwtAuthProviderReader.RsaVerifyAlgorithms[algorithm](
					publicKey,
					bytesToSign,
					sentSignatureBytes);

				if (verified)
				{
					return true;
				}
			}

			return false;
		}


		public void Register(IAppHost appHost, AuthFeature feature)
		{
			//var isHmac = HmacAlgorithms.ContainsKey(HashAlgorithm);
			//var isRsa = RsaSignAlgorithms.ContainsKey(HashAlgorithm);
			//if (!isHmac && !isRsa)
			//	throw new NotSupportedException("Invalid algoritm: " + HashAlgorithm);

			//if (isHmac && AuthKey == null)
			//	throw new ArgumentNullException("AuthKey", "An AuthKey is Required to use JWT, e.g: new JwtAuthProvider { AuthKey = AesUtils.CreateKey() }");
			//else if (isRsa && PrivateKey == null && PublicKey == null)
			//	throw new ArgumentNullException("PrivateKey", "PrivateKey is Required to use JWT with " + HashAlgorithm);

			//if (KeyId == null)
			//	KeyId = GetKeyId();

			//foreach (var registerService in ServiceRoutes)
			//{
			//	appHost.RegisterService(registerService.Key, registerService.Value);
			//}

			feature.AuthResponseDecorator = _jwtAuthProviderReader.AuthenticateResponseDecorator;
		}

		// private within innerProvider
		private IAuthSession CreateSessionFromPayload(IRequest req, JsonObject jwtPayload)
		{
			var expiresAt = GetUnixTime(jwtPayload, "exp");
			var secondsSinceEpoch = DateTime.UtcNow.ToUnixTime();
			if (secondsSinceEpoch >= expiresAt)
				throw new TokenException(ErrorMessages.TokenExpired);

			if (InvalidateTokensIssuedBefore != null)
			{
				var issuedAt = GetUnixTime(jwtPayload, "iat");
				if (issuedAt == null || issuedAt < InvalidateTokensIssuedBefore.Value.ToUnixTime())
					throw new TokenException(ErrorMessages.TokenInvalidated);
			}

			string audience;
			if (jwtPayload.TryGetValue("aud", out audience))
			{
				if (audience != Audience)
					throw new TokenException("Invalid Audience: " + audience);
			}

			var sessionId = jwtPayload.GetValue("jid", SessionExtensions.CreateRandomSessionId);
			var session = SessionFeature.CreateNewSession(req, sessionId);

			session.PopulateFromMap(jwtPayload);

			if (_jwtAuthProviderReader.PopulateSessionFilter != null)
				_jwtAuthProviderReader.PopulateSessionFilter(session, jwtPayload, req);

			HostContext.AppHost.OnSessionFilter(session, sessionId);
			return session;
		}

		static int? GetUnixTime(Dictionary<string, string> jwtPayload, string key)
		{
			string value;
			if (jwtPayload.TryGetValue(key, out value) && !string.IsNullOrEmpty(value))
			{
				try
				{
					return int.Parse(value);
				}
				catch (Exception)
				{
					throw new TokenException("Claim '{0}' must be a Unix Timestamp".Fmt(key));
				}
			}
			return null;
		}
	}
}