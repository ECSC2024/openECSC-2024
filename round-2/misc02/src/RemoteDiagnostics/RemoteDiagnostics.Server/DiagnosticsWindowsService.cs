using System;
using System.Collections;
using System.ComponentModel;
using System.Configuration.Install;
using System.ServiceModel;
using System.ServiceProcess;

namespace RemoteDiagnostics.Server
{
    internal class DiagnosticsWindowsService : ServiceBase
    {
        public ServiceHost serviceHost = null;

        public DiagnosticsWindowsService()
        {
            ServiceName = "DiagnosticsService";
        }
        
        protected override void OnStart(string[] args)
        {
            serviceHost?.Close();
            serviceHost = Entry.StartService();
        }

        protected override void OnStop()
        {
            if (serviceHost != null)
            {
                serviceHost.Close();
                serviceHost = null;
            }
        }
    }

    [RunInstaller(true)]
    public class DiagnosticsInstaller : Installer
    {
        private readonly ServiceProcessInstaller process;
        private readonly ServiceInstaller service;

        public DiagnosticsInstaller()
        {
            process = new ServiceProcessInstaller
            {
                Account = ServiceAccount.LocalSystem
            };
            service = new ServiceInstaller
            {
                ServiceName = "DiagnosticsService",
                StartType = ServiceStartMode.Automatic,
            };
            Installers.Add(process);
            Installers.Add(service);
        }

        protected override void OnBeforeInstall(IDictionary savedState)
        {
            base.OnBeforeInstall(savedState);
            Context.Parameters["assemblyPath"] = string.Format("\"{0}\" /svc", Context.Parameters["assemblyPath"]);
        }
    }
}
