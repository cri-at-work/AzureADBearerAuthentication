namespace ServiceStack.Authentication.Aad.SelfHostTest
{
    public class Services : Service
    {
	    public object Any(SecureResourceRequest request)
        {
	        var session = GetSession();

            var html = @"
<html><body>
<p>
Success!  You are looking at a secure resource.
</p>
<p>
<a href='/auth/logout'>Sign out {0} {1}</a>
</p>
</body></html>
";
						return new HttpResult(html.Fmt(session.FirstName, session.LastName), "text/html");
        }
    }
}