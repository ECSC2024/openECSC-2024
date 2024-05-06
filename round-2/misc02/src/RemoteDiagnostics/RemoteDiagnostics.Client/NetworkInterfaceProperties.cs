using RemoteDiagnostics.Contract;
using System.Data;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace RemoteDiagnostics.Client
{
    public partial class NetworkInterfaceProperties : Form
    {
        public TaskCompletionSource<bool> simWindowLoaded = new TaskCompletionSource<bool>();

        public NetworkInterfaceProperties(Interface networkInterface)
        {
            InitializeComponent();
            Text = networkInterface.Name;
            interfacePropertiesTable.Rows.Add("Name", networkInterface.Name);
            interfacePropertiesTable.Rows.Add("Description", networkInterface.Description);
            interfacePropertiesTable.Rows.Add("Status", networkInterface.Status.ToString());
            interfacePropertiesTable.Rows.Add("DNS suffix", networkInterface.DnsSuffix);
            interfacePropertiesTable.Rows.Add("DNS servers", string.Join(", ", networkInterface.DnsAddresses.Select(dnsAddr => dnsAddr.ToString())));
            interfacePropertiesTable.Rows.Add("IP addresses", string.Join(", ", networkInterface.UnicastAddresses.Select(uip => uip.Address.ToString())));
            interfacePropertiesTable.Rows.Add("IP masks", string.Join(", ", networkInterface.UnicastAddresses.Select(uip => uip.IPv4Mask.ToString())));
            interfacePropertiesTable.Rows.Add("Gateways", string.Join(", ", networkInterface.GatewayAddresses.Select(gip => gip.Address.ToString())));
            interfacePropertiesTable.Rows.Add("DHCP servers", string.Join(", ", networkInterface.DhcpServerAddresses.Select(ip => ip.ToString())));
        }

        private void NetworkInterfaceProperties_Shown(object sender, System.EventArgs e)
        {
            simWindowLoaded.TrySetResult(true);
        }
    }
}
