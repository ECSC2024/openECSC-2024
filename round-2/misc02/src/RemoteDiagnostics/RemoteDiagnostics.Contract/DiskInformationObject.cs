using System.IO;
using System.Runtime.Serialization;

namespace RemoteDiagnostics.Contract
{
    [DataContract]
    public class DiskInformationObject
    {
        [DataMember]
        public DriveInfo[] Drives { get; set; }
    }
}
