using System;
using System.Runtime.Serialization;

namespace RemoteDiagnostics.Contract
{
    [DataContract]
    [KnownType(typeof(Version))]
    [KnownType(typeof(PlatformID))]
    public class HostInformationObject
    {
        [DataMember]
        public string MachineName { get; set; }

        [DataMember]
        public OperatingSystem OSVersion { get; set; }

        [DataMember]
        public int ProcessorCount { get; set; }
    }
}
