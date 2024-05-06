using RemoteDiagnostics.Contract;
using System;
using System.ServiceModel;
using System.ServiceProcess;

namespace RemoteDiagnostics.Server
{
    internal class Entry
    {
        static void Main(string[] args)
        {
            foreach (var arg in args)
            {
                if (arg == "/svc")
                {
                    ServiceBase.Run(new DiagnosticsWindowsService());
                    return;
                }
            }

            StartService();
            Console.WriteLine("[*] Listening...");
            Console.ReadLine();
        }

        internal static ServiceHost StartService()
        {
            DiagnosticsBinding binding = new DiagnosticsBinding();
            Uri uri = new Uri("net.tcp://localhost:2024");

            ServiceHost serviceHost = new ServiceHost(typeof(DiagnosticsService), uri);
            serviceHost.AddServiceEndpoint(typeof(IDiagnostics), binding, "Diagnostics");
            serviceHost.Open();

            return serviceHost;
        }
    }
}
