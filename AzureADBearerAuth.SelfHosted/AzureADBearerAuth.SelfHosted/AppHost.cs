using System.Collections.Generic;
using Funq;
using ServiceStack;
using ServiceStack.Auth;
using ServiceStack.Authentication.Aad;
using ServiceStack.Authentication.Aad.SelfHostTest;
using ServiceStack.Configuration;
using ServiceStack.Logging;

namespace AzureADBearerAuth.SelfHosted
{
	public class AppHost : AppSelfHostBase
	{
		public AppHost()
			: base("SelfHostTest", typeof(Services).Assembly)
		{
			LogManager.LogFactory = new ConsoleLogFactory();
		}

		public override void Configure(Container container)
		{

		//<add key="oauth.aad.TenantId" value="b47cbfa7-58e2-4880-8aba-8e4c29db1f42" />
		//<add key="oauth.aad.ClientId" value="8b064a41-8b59-41f6-b4ab-1c44ed077011" />
		//<add key="oauth.aad.DomainHint" value="d3dev.onmicrosoft.com" />
		//<add key="oauth.aad.ClientSecret" value="MfKvG2GFuRq0B6lno9yxdStJXShhU0GvkO2RkpYmn/Y=" />

		//<!-- CallbackUrl MUST match a REPLY URL configured in the AAD App. -->
		//<add key="oauth.aad.CallbackUrl" value="http://localhost:8088/auth/aad"/>-->

			var appSettings = new DictionarySettings(new Dictionary<string, string>
			{
				{"oauth.aad.TenantId", AzureADSettings.TenantId},
				{"oauth.aad.DomainHint", AzureADSettings.Tenant},
				{"oauth.aad.ClientId", AzureADSettings.TodoListDemo_ClientId},
				{"oauth.aad.ClientSecret", AzureADSettings.TodoListDemo_ClientSecret},
				{"oauth.aad.CallbackUrl", "http://localhost:8088/auth/aad"}
			});

			var authProviders = new IAuthProvider[] { new AadAuthProvider(appSettings) };
			Plugins.Add(new AuthFeature(
					() => new AuthUserSession(),
					authProviders,
					htmlRedirect: "/auth/aad"));
		}
	}
}
