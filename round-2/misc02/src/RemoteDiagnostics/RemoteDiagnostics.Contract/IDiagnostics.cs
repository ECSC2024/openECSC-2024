using System.ServiceModel;

namespace RemoteDiagnostics.Contract
{
    [ServiceContract]
    public interface IDiagnostics
    {
        [OperationContract]
        [FaultContract(typeof(Fault))]
        bool Ping();

        [OperationContract]
        [FaultContract(typeof(Fault))]
        WhoAmIObject WhoAmI();

        [OperationContract]
        [FaultContract(typeof(Fault))]
        DiskInformationObject GetDiskInformation();

        [OperationContract]
        [FaultContract(typeof(Fault))]
        DirectoryInformationObject GetDirectoryInformation(string path);

        [OperationContract]
        [FaultContract(typeof(Fault))]
        HostInformationObject GetHostInformation();

        [OperationContract]
        [FaultContract(typeof(Fault))]
        NetworkInformationObject GetNetworkInformation();

        [OperationContract]
        [FaultContract(typeof(Fault))]
        ProcessObject[] GetProcesses();

        [OperationContract]
        [FaultContract(typeof(Fault))]
        ProcessSecurityObject GetProcessSecurity(int processId);
    }
}
