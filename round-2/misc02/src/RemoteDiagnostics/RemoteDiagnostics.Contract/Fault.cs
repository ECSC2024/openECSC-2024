using System;
using System.Runtime.Serialization;
using System.ServiceModel;

namespace RemoteDiagnostics.Contract
{
    [DataContract]
    public class Fault
    {
        [DataMember]
        public string Message { get; set; }

        public static Fault CreateFromException(Exception ex)
        {
            return new Fault
            {
                Message = ex.Message,
            };
        }

        public static FaultReason CreateFaultReason(Exception ex)
        {
            return new FaultReason(ex.Message);
        }
    }
}
