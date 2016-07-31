using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ServiceStack;
using ServiceStack.Text;

namespace AzureADBearerAuth.SelfHosted
{
	class Program
	{
		static void Main(string[] args)
		{
			var port = 8088;
			new AppHost().Init().Start("http://*:{0}/".Fmt(port));
			"ServiceStack SelfHost listening at http://localhost:{0}".Fmt(port).Print();
			Process.Start("http://localhost:{0}/secure".Fmt(port));
			Console.ReadLine();
		}
	}
}
