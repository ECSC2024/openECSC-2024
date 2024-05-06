using System.Runtime.Serialization;
using System.Security.Claims;

namespace RemoteDiagnostics.Contract
{
    [DataContract]
    public class WhoAmIObject
    {
        [DataMember]
        public ClaimsIdentity Identity { get; set; }
    }
}
