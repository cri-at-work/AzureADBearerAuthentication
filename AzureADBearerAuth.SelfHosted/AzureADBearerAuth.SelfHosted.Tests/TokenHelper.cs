using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace AzureADBearerAuth.SelfHosted.Tests
{
	internal class TokenHelper
	{
		public const string AzureAdInstance = "https://login.microsoftonline.com/{0}";

		private readonly string _audience;
		private readonly AuthenticationContext _authContext;

		public TokenHelper(string audience, string tenant)
		{
			_audience = audience;
			var authority = String.Format(CultureInfo.InvariantCulture, AzureAdInstance, tenant);
			_authContext = new AuthenticationContext(authority);
		}

		public async Task<string> CreateClientToken(ClientCredential clientCredential)
		{
			//client token
			//var token =
			//	"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik1uQ19WWmNBVGZNNXBPWWlKSE1iYTlnb0VLWSIsImtpZCI6Ik1uQ19WWmNBVGZNNXBPWWlKSE1iYTlnb0VLWSJ9.eyJhdWQiOiJodHRwczovL2NvbnRvc28ub25taWNyb3NvZnQuY29tL1RvZG9MaXN0U2VydmljZSIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0L2I0N2NiZmE3LTU4ZTItNDg4MC04YWJhLThlNGMyOWRiMWY0Mi8iLCJpYXQiOjE0Njk2Mjc4ODMsIm5iZiI6MTQ2OTYyNzg4MywiZXhwIjoxNDY5NjMxNzgzLCJhcHBpZCI6IjhiMDY0YTQxLThiNTktNDFmNi1iNGFiLTFjNDRlZDA3NzAxMSIsImFwcGlkYWNyIjoiMSIsImlkcCI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0L2I0N2NiZmE3LTU4ZTItNDg4MC04YWJhLThlNGMyOWRiMWY0Mi8iLCJvaWQiOiIyYTc1NzI0Zi00NWNjLTQ2YmEtYjhmYi1iNzJiYTg0OWQ4MTEiLCJzdWIiOiIyYTc1NzI0Zi00NWNjLTQ2YmEtYjhmYi1iNzJiYTg0OWQ4MTEiLCJ0aWQiOiJiNDdjYmZhNy01OGUyLTQ4ODAtOGFiYS04ZTRjMjlkYjFmNDIiLCJ2ZXIiOiIxLjAifQ.eEOrfNf0VDzpibvS6FvVYXLkI05LEbBeHxBqp8KfMttmsEbAkCRAwLp-L_ICv10ckzITypOhzOZ4DLQN_jw2qrbAT_MDdisLC2-IkhjYKAzKfscedIs_YvovJSJ98UAg_ye0asAyoe-eeD89Avo42gdp_L64vwWYXU6kxW799v8MY9xVojRJl5awI7oajE9ujZvcMo1vTtu8VtTufLr7KSMlkEApKlvA2dFnh6Q1HkaLSvOikK25YNke_9wCyxcUwYkxwCLD1gQvUkSTRL9LKW33CNeJAy6El2LBdN37ZPnuMmQf5E4j4vtN04yG4hdsos4dKMif4MUNX6P0f7e8qQ";


			//
			// Get an access token from Azure AD using client credentials.
			// If the attempt to get a token fails because the server is unavailable, retry twice after 3 seconds each.
			//
			AuthenticationResult result = null;
			int retryCount = 0;
			bool retry = false;

			do
			{
				retry = false;
				try
				{
					// ADAL includes an in memory cache, so this call will only send a message to the server if the cached token is expired.
					result = await _authContext.AcquireTokenAsync(_audience, clientCredential);
				}
				catch (AdalException ex)
				{
					if (ex.ErrorCode == "temporarily_unavailable")
					{
						retry = true;
						retryCount++;
						Thread.Sleep(3000);
					}

					Console.WriteLine(
						String.Format("An error occurred while acquiring a token\nTime: {0}\nError: {1}\nRetry: {2}\n",
							DateTime.Now.ToString(),
							ex.ToString(),
							retry.ToString()));
				}

			} while ((retry == true) && (retryCount < 3));

			if (result == null)
			{
				throw new ApplicationException("Canceling attempt to contact To Do list service.\n");
			}

			return result.AccessToken;
		}

		public async Task<string> CreateUserToken(string clientId, UserPasswordCredential userCredential)
		{
			//client token
			//var token =
			//	"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik1uQ19WWmNBVGZNNXBPWWlKSE1iYTlnb0VLWSIsImtpZCI6Ik1uQ19WWmNBVGZNNXBPWWlKSE1iYTlnb0VLWSJ9.eyJhdWQiOiJodHRwczovL2NvbnRvc28ub25taWNyb3NvZnQuY29tL1RvZG9MaXN0U2VydmljZSIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0L2I0N2NiZmE3LTU4ZTItNDg4MC04YWJhLThlNGMyOWRiMWY0Mi8iLCJpYXQiOjE0Njk2Mjc4ODMsIm5iZiI6MTQ2OTYyNzg4MywiZXhwIjoxNDY5NjMxNzgzLCJhcHBpZCI6IjhiMDY0YTQxLThiNTktNDFmNi1iNGFiLTFjNDRlZDA3NzAxMSIsImFwcGlkYWNyIjoiMSIsImlkcCI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0L2I0N2NiZmE3LTU4ZTItNDg4MC04YWJhLThlNGMyOWRiMWY0Mi8iLCJvaWQiOiIyYTc1NzI0Zi00NWNjLTQ2YmEtYjhmYi1iNzJiYTg0OWQ4MTEiLCJzdWIiOiIyYTc1NzI0Zi00NWNjLTQ2YmEtYjhmYi1iNzJiYTg0OWQ4MTEiLCJ0aWQiOiJiNDdjYmZhNy01OGUyLTQ4ODAtOGFiYS04ZTRjMjlkYjFmNDIiLCJ2ZXIiOiIxLjAifQ.eEOrfNf0VDzpibvS6FvVYXLkI05LEbBeHxBqp8KfMttmsEbAkCRAwLp-L_ICv10ckzITypOhzOZ4DLQN_jw2qrbAT_MDdisLC2-IkhjYKAzKfscedIs_YvovJSJ98UAg_ye0asAyoe-eeD89Avo42gdp_L64vwWYXU6kxW799v8MY9xVojRJl5awI7oajE9ujZvcMo1vTtu8VtTufLr7KSMlkEApKlvA2dFnh6Q1HkaLSvOikK25YNke_9wCyxcUwYkxwCLD1gQvUkSTRL9LKW33CNeJAy6El2LBdN37ZPnuMmQf5E4j4vtN04yG4hdsos4dKMif4MUNX6P0f7e8qQ";


			//
			// Get an access token from Azure AD using client credentials.
			// If the attempt to get a token fails because the server is unavailable, retry twice after 3 seconds each.
			//
			AuthenticationResult result = null;
			int retryCount = 0;
			bool retry = false;

			do
			{
				retry = false;
				try
				{
					// ADAL includes an in memory cache, so this call will only send a message to the server if the cached token is expired.
					result = await _authContext.AcquireTokenAsync(_audience, clientId, userCredential);
				}
				catch (AdalException ex)
				{
					if (ex.ErrorCode == "temporarily_unavailable")
					{
						retry = true;
						retryCount++;
						Thread.Sleep(3000);
					}

					Console.WriteLine(
						String.Format("An error occurred while acquiring a token\nTime: {0}\nError: {1}\nRetry: {2}\n",
							DateTime.Now.ToString(),
							ex.ToString(),
							retry.ToString()));
				}

			} while ((retry == true) && (retryCount < 3));

			if (result == null)
			{
				throw new ApplicationException("Canceling attempt to contact To Do list service.\n");
			}

			return result.AccessToken;
		}
	}
}
