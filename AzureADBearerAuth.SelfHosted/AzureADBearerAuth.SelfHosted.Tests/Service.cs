using ServiceStack;

namespace AzureADBearerAuth.SelfHosted.Tests
{
	[Route("/secured", "GET")]
	public class Secured : IReturn<SecuredResponse>
	{
		public string Name { get; set; }
	}

	public class SecuredResponse
	{
		public string Result { get; set; }

		public ResponseStatus ResponseStatus { get; set; }
	}

	[Authenticate]
	public class SecureService : Service
	{
		public object Any(Secured request)
		{
			return new SecuredResponse { Result = request.Name };
		}
	}
}
