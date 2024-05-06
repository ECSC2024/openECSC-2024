using RemoteDiagnostics.Contract;
using System;
using System.Net;
using System.Security.Principal;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.Threading.Tasks;

namespace RemoteDiagnostics.Client
{
    internal class DiagnosticsClient
    {
        public static DiagnosticsProxy client = null;
        public static string host = null;

        internal static async Task Connect(string host, string username = null, string password = null)
        {
            if (!host.Contains(":"))
            {
                host += ":2024";
            }

            NetworkCredential credentials = null;
            if (username != null && password != null)
            {
                credentials = new NetworkCredential(username, password);
            }

            EndpointAddress endpoint = new EndpointAddress(string.Format("net.tcp://{0}/Diagnostics", host));

            DiagnosticsBinding binding = new DiagnosticsBinding();

            client = new DiagnosticsProxy(binding, endpoint, credentials);

            await Task.Run(() =>
            {
                if (client.Ping() != true)
                {
                    throw new Exception(string.Format("Failed to ping host: {0}", host));
                }
            });

            DiagnosticsClient.host = host;
        }

        internal static void Close()
        {
            client?.Close();
            client = null;
        }
    }

    internal partial class DiagnosticsProxy : ClientBase<IDiagnostics>, IDiagnostics
    {
        public DiagnosticsProxy(Binding binding, EndpointAddress remoteAddress, NetworkCredential networkCredential = null) : base(binding, remoteAddress)
        {
            ClientCredentials.Windows.AllowedImpersonationLevel = TokenImpersonationLevel.Impersonation;
            ClientCredentials.Windows.ClientCredential = networkCredential ?? CredentialCache.DefaultNetworkCredentials;
        }

        public bool Ping()
        {
            return Channel.Ping();
        }

        public WhoAmIObject WhoAmI()
        {
            return Channel.WhoAmI();
        }

        public DiskInformationObject GetDiskInformation()
        {
            return Channel.GetDiskInformation();
        }

        public DirectoryInformationObject GetDirectoryInformation(string path)
        {
            return Channel.GetDirectoryInformation(path);
        }

        public HostInformationObject GetHostInformation()
        {
            return Channel.GetHostInformation();
        }

        public NetworkInformationObject GetNetworkInformation()
        {
            return Channel.GetNetworkInformation();
        }

        public ProcessObject[] GetProcesses()
        {
            return Channel.GetProcesses();
        }

        public ProcessSecurityObject GetProcessSecurity(int processId)
        {
            return Channel.GetProcessSecurity(processId);
        }
    }
}
