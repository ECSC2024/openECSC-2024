using System.Net.Security;
using System.ServiceModel;

namespace RemoteDiagnostics.Contract
{
    public class DiagnosticsBinding : NetTcpBinding
    {
        public DiagnosticsBinding()
        {
            Security.Mode = SecurityMode.Transport;
            Security.Transport.ClientCredentialType = TcpClientCredentialType.Windows;
            Security.Transport.ProtectionLevel = ProtectionLevel.None;
        }
    }
}
