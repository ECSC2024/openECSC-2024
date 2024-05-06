using System.IO;
using System.Runtime.Serialization;

namespace RemoteDiagnostics.Contract
{
    [DataContract]
    [KnownType(typeof(DirectoryInfo))]
    [KnownType(typeof(FileInfo))]
    public class DirectoryInformationObject
    {
        [DataMember]
        public FileSystemInfo Current { get; set; }

        [DataMember]
        public FileSystemInfo Parent { get; set; }

        [DataMember]
        public FileSystemInfo Root { get; set; }

        [DataMember]
        public FileSystemInfo[] Children { get; set; }
    }
}
