using System.Net.NetworkInformation;
using System.Net;
using System.Runtime.Serialization;

namespace RemoteDiagnostics.Contract
{
    [DataContract]
    public class UnicastIPAddress
    {
        [DataMember]
        public long PreferredLifetime { get; set; }

        [DataMember]
        public long ValidLifetime { get; set; }

        [DataMember]
        public long DhcpLeaseLifetime { get; set; }

        [DataMember]
        public IPAddress IPv4Mask { get; set; }

        [DataMember]
        public int PrefixLength { get; set; }

        [DataMember]
        public IPAddress Address { get; set; }
    }

    [DataContract]
    public class GatewayIPAddress
    {
        [DataMember]
        public IPAddress Address { get; set; }
    }

    [DataContract]
    public class Interface
    {
        [DataMember]
        public string Name { get; set; }

        [DataMember]
        public string Description { get; set; }

        [DataMember]
        public OperationalStatus Status { get; set; }

        [DataMember]
        public string DnsSuffix { get; set; }

        [DataMember]
        public IPAddress[] DnsAddresses { get; set; }

        [DataMember]
        public UnicastIPAddress[] UnicastAddresses { get; set; }

        [DataMember]
        public GatewayIPAddress[] GatewayAddresses { get; set; }

        [DataMember]
        public IPAddress[] DhcpServerAddresses { get; set; }
    }

    [DataContract]
    public class NetworkInformationObject
    {
        [DataMember]
        public Interface[] Interfaces { get; set; }
    }
}
