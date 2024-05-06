using System.Runtime.Serialization;

namespace RemoteDiagnostics.Contract
{
    [DataContract]
    public class ProcessObject
    {
        [DataMember]
        public int Id { get; set; }
        [DataMember]
        public string MainWindowTitle { get; set; }
        [DataMember]
        public long NonpagedSystemMemorySize { get; set; }
        [DataMember]
        public long PagedMemorySize { get; set; }
        [DataMember]
        public long PagedSystemMemorySize { get; set; }
        [DataMember]
        public long PrivateMemorySize { get; set; }
        [DataMember]
        public string ProcessName { get; set; }
        [DataMember]
        public bool Running { get; set; }
        [DataMember]
        public int SessionId { get; set; }
        [DataMember]
        public long VirtualMemorySize { get; set; }
        [DataMember]
        public long PhysicalMemorySize { get; set; }
    }
}
