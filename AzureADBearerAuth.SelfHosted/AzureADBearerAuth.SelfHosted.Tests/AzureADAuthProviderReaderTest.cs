using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Funq;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using NUnit.Framework;
using ServiceStack;
using ServiceStack.Auth;
using ServiceStack.Authentication.Aad;
using ServiceStack.Configuration;

namespace AzureADBearerAuth.SelfHosted.Tests
{

	public class AzureADAuthProviderReaderTests
	{
		public const string ListeningOn = "http://localhost:2337/";
		protected readonly ServiceStackHost appHost;
		private readonly RSAParameters privateKey;
		private static string tenant = AzureADSettings.Tenant;
		private static string audience = AzureADSettings.Audience;
		private static AuthenticationContext authContext = null;
		private static ClientCredential clientCredential = null;
		private static UserPasswordCredential userCredential = null;
		private TokenHelper _tokenHelper;

		class AzureADAuthProviderReaderAppHost : AppHostHttpListenerBase
		{
			public AzureADAuthProviderReaderAppHost()
				: base("Test AzureADAuthProviderReader", typeof(JwtAuthProviderReaderTests).Assembly) { }

			public override void Configure(Container container)
			{

				Plugins.Add(new AuthFeature(() => new AuthUserSession(),
						new IAuthProvider[] {
                        new AzureADAuthProviderReader(AppSettings),
                    }));
			}
		}

		public AzureADAuthProviderReaderTests()
		{
			ServicePointManager.ServerCertificateValidationCallback
				= new RemoteCertificateValidationCallback(OnValidationCallback);

			clientCredential = new ClientCredential(
				AzureADSettings.TodoListDemo_ClientId,
				AzureADSettings.TodoListDemo_ClientSecret);

			userCredential = new UserPasswordCredential(
				AzureADSettings.User1_UserName,
				AzureADSettings.User1_Password);

			_tokenHelper = new TokenHelper(audience, tenant);

			appHost = new AzureADAuthProviderReaderAppHost
			{
				AppSettings = new DictionarySettings(new Dictionary<string, string> {
                    { "aadr.RequireSecureConnection", "False" },
										{"aadr.Audience", audience},
										{"aadr.Tenant", tenant},
                })
			}
			.Init()
			.Start("http://*:2337/");
		}

		public static bool OnValidationCallback(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors errors)
		{
			return true;
		}

		[TestFixtureTearDown]
		public void TestFixtureTearDown()
		{
			appHost.Dispose();
		}

		[Test]
		public void Can_authenticate_with_RSA_client_token_created_from_AzureAD()
		{
			var token = _tokenHelper.CreateClientToken(clientCredential).Result;

			var client = new JsonServiceClient(ListeningOn)
			{
				BearerToken = token
			};

			var request = new Secured { Name = "test" };
			var response = client.Get(request);
			Assert.That(response.Result, Is.EqualTo(request.Name));
		}

		[Test]
		public void Can_authenticate_with_RSA_user_token_created_from_AzureAD()
		{
			var token = _tokenHelper.CreateUserToken(
				AzureADSettings.testclient_ClientId,
				userCredential).Result;

			var client = new JsonServiceClient(ListeningOn)
			{
				BearerToken = token
			};

			var request = new Secured { Name = "test" };
			var response = client.Get(request);
			Assert.That(response.Result, Is.EqualTo(request.Name));
		}

		public static void AssertAdditionalMetadataWasPopulated(AuthUserSession session)
		{
			Assert.That(session.Id, Is.EqualTo("SESSIONID"));
			Assert.That(session.ReferrerUrl, Is.EqualTo("http://example.org/ReferrerUrl"));
			Assert.That(session.UserAuthName, Is.EqualTo("UserAuthName"));
			Assert.That(session.TwitterUserId, Is.EqualTo("TwitterUserId"));
			Assert.That(session.TwitterScreenName, Is.EqualTo("TwitterScreenName"));
			Assert.That(session.FacebookUserId, Is.EqualTo("FacebookUserId"));
			Assert.That(session.FirstName, Is.EqualTo("FirstName"));
			Assert.That(session.LastName, Is.EqualTo("LastName"));
			Assert.That(session.Company, Is.EqualTo("Company"));
			Assert.That(session.PrimaryEmail, Is.EqualTo("PrimaryEmail"));
			Assert.That(session.PhoneNumber, Is.EqualTo("PhoneNumber"));
			Assert.That(session.BirthDate, Is.EqualTo(new DateTime(2000, 1, 1, 0, 0, 0, DateTimeKind.Utc)));
			Assert.That(session.Address, Is.EqualTo("Address"));
			Assert.That(session.Address2, Is.EqualTo("Address2"));
			Assert.That(session.City, Is.EqualTo("City"));
			Assert.That(session.State, Is.EqualTo("State"));
			Assert.That(session.Country, Is.EqualTo("Country"));
			Assert.That(session.Culture, Is.EqualTo("Culture"));
			Assert.That(session.FullName, Is.EqualTo("FullName"));
			Assert.That(session.Gender, Is.EqualTo("Gender"));
			Assert.That(session.Language, Is.EqualTo("Language"));
			Assert.That(session.MailAddress, Is.EqualTo("MailAddress"));
			Assert.That(session.Nickname, Is.EqualTo("Nickname"));
			Assert.That(session.PostalCode, Is.EqualTo("PostalCode"));
			Assert.That(session.TimeZone, Is.EqualTo("TimeZone"));
			Assert.That(session.RequestTokenSecret, Is.EqualTo("RequestTokenSecret"));
			Assert.That(session.CreatedAt, Is.EqualTo(new DateTime(2010, 1, 1, 0, 0, 0, DateTimeKind.Utc)));
			Assert.That(session.LastModified, Is.EqualTo(new DateTime(2016, 1, 1, 0, 0, 0, DateTimeKind.Utc)));
			Assert.That(session.Sequence, Is.EqualTo("Sequence"));
			Assert.That(session.Tag, Is.EqualTo(1));
		}
	}
}
