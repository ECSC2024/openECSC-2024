using RemoteDiagnostics.Contract;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Net;
using System.Security.Claims;
using System.Security.Principal;
using System.ServiceModel;

namespace ServerPOC02
{
    // Token: 0x02000002 RID: 2
    [ServiceBehavior(InstanceContextMode = InstanceContextMode.Single, AddressFilterMode = AddressFilterMode.Any)]
    public class DiagnosticsService : IDiagnostics
    {
        // Token: 0x06000001 RID: 1 RVA: 0x00002048 File Offset: 0x00000248
        public bool Ping()
        {
            return true;
        }

        // Token: 0x06000002 RID: 2 RVA: 0x0000204C File Offset: 0x0000024C
        [OperationBehavior(Impersonation = ImpersonationOption.Required)]
        public WhoAmIObject WhoAmI()
        {
            WhoAmIObject result;
            try
            {
                result = new WhoAmIObject
                {
                    Identity = new ClaimsIdentity(WindowsIdentity.GetCurrent())
                };
            }
            catch (Exception ex)
            {
                throw new FaultException<Fault>(Fault.CreateFromException(ex), Fault.CreateFaultReason(ex));
            }
            return result;
        }

        // Token: 0x06000003 RID: 3 RVA: 0x00002098 File Offset: 0x00000298
        [OperationBehavior(Impersonation = ImpersonationOption.Required)]
        public DiskInformationObject GetDiskInformation()
        {
            DiskInformationObject result;
            try
            {
                result = new DiskInformationObject
                {
                    Drives = DriveInfo.GetDrives()
                };
            }
            catch (Exception ex)
            {
                throw new FaultException<Fault>(Fault.CreateFromException(ex), Fault.CreateFaultReason(ex));
            }
            return result;
        }

        // Token: 0x06000004 RID: 4 RVA: 0x000020DC File Offset: 0x000002DC
        [OperationBehavior(Impersonation = ImpersonationOption.Required)]
        public DirectoryInformationObject GetDirectoryInformation(string path)
        {
            DirectoryInformationObject result;
            try
            {
                DirectoryInfo directoryInfo = new DirectoryInfo(path);
                FileSystemInfo[] children = null;
                if (directoryInfo.Exists)
                {
                    children = directoryInfo.GetFileSystemInfos();
                }
                result = new DirectoryInformationObject
                {
                    Current = directoryInfo,
                    Parent = directoryInfo.Parent,
                    Root = directoryInfo.Root,
                    Children = children
                };
            }
            catch (Exception ex)
            {
                throw new FaultException<Fault>(Fault.CreateFromException(ex), Fault.CreateFaultReason(ex));
            }
            return result;
        }

        // Token: 0x06000005 RID: 5 RVA: 0x00002154 File Offset: 0x00000354
        [OperationBehavior(Impersonation = ImpersonationOption.Required)]
        public HostInformationObject GetHostInformation()
        {
            HostInformationObject result;
            try
            {
                result = new HostInformationObject
                {
                    MachineName = Environment.MachineName,
                    OSVersion = Environment.OSVersion,
                    ProcessorCount = Environment.ProcessorCount
                };
            }
            catch (Exception ex)
            {
                throw new FaultException<Fault>(Fault.CreateFromException(ex), Fault.CreateFaultReason(ex));
            }
            return result;
        }

        // Token: 0x06000006 RID: 6 RVA: 0x000021B0 File Offset: 0x000003B0
        [OperationBehavior(Impersonation = ImpersonationOption.Required)]
        public NetworkInformationObject GetNetworkInformation()
        {
            NetworkInformationObject result;
            try
            {
                NetworkInterface.GetAllNetworkInterfaces().Select(delegate (NetworkInterface ni)
                {
                    IPInterfaceProperties ipproperties = ni.GetIPProperties();
                    Interface @interface = new Interface();
                    @interface.Name = ni.Name;
                    @interface.Description = ni.Description;
                    @interface.Status = ni.OperationalStatus;
                    @interface.InterfaceType = ni.NetworkInterfaceType;
                    @interface.DnsSuffix = ipproperties.DnsSuffix;
                    @interface.DnsAddresses = ipproperties.DnsAddresses.ToArray<IPAddress>();
                    @interface.UnicastAddresses = (from addr in ipproperties.UnicastAddresses
                                                   select new UnicastIPAddress
                                                   {
                                                       PreferredLifetime = addr.AddressPreferredLifetime,
                                                       ValidLifetime = addr.AddressValidLifetime,
                                                       DhcpLeaseLifetime = addr.DhcpLeaseLifetime,
                                                       IPv4Mask = addr.IPv4Mask,
                                                       PrefixLength = addr.PrefixLength,
                                                       Address = addr.Address
                                                   }).ToArray<UnicastIPAddress>();
                    @interface.GatewayAddresses = (from addr in ipproperties.GatewayAddresses
                                                   select new GatewayIPAddress
                                                   {
                                                       Address = addr.Address
                                                   }).ToArray<GatewayIPAddress>();
                    @interface.DhcpServerAddresses = ipproperties.DhcpServerAddresses.ToArray<IPAddress>();
                    return @interface;
                }).ToArray<Interface>();
                NetworkInformationObject networkInformationObject = new NetworkInformationObject();
                networkInformationObject.Interfaces = NetworkInterface.GetAllNetworkInterfaces().Select(delegate (NetworkInterface ni)
                {
                    IPInterfaceProperties ipproperties = ni.GetIPProperties();
                    Interface @interface = new Interface();
                    @interface.Name = ni.Name;
                    @interface.Description = ni.Description;
                    @interface.Status = ni.OperationalStatus;
                    @interface.InterfaceType = ni.NetworkInterfaceType;
                    @interface.DnsSuffix = ipproperties.DnsSuffix;
                    @interface.DnsAddresses = ipproperties.DnsAddresses.ToArray<IPAddress>();
                    @interface.UnicastAddresses = (from addr in ipproperties.UnicastAddresses
                                                   select new UnicastIPAddress
                                                   {
                                                       PreferredLifetime = addr.AddressPreferredLifetime,
                                                       ValidLifetime = addr.AddressValidLifetime,
                                                       DhcpLeaseLifetime = addr.DhcpLeaseLifetime,
                                                       IPv4Mask = addr.IPv4Mask,
                                                       PrefixLength = addr.PrefixLength,
                                                       Address = addr.Address
                                                   }).ToArray<UnicastIPAddress>();
                    @interface.GatewayAddresses = (from addr in ipproperties.GatewayAddresses
                                                   select new GatewayIPAddress
                                                   {
                                                       Address = addr.Address
                                                   }).ToArray<GatewayIPAddress>();
                    @interface.DhcpServerAddresses = ipproperties.DhcpServerAddresses.ToArray<IPAddress>();
                    return @interface;
                }).ToArray<Interface>();
                result = networkInformationObject;
            }
            catch (Exception ex)
            {
                throw new FaultException<Fault>(Fault.CreateFromException(ex), Fault.CreateFaultReason(ex));
            }
            return result;
        }

        // Token: 0x06000007 RID: 7 RVA: 0x0000224C File Offset: 0x0000044C
        [OperationBehavior(Impersonation = ImpersonationOption.Required)]
        public ProcessObject[] GetProcesses()
        {
            ProcessObject[] result;
            try
            {
                result = (from process in Process.GetProcesses()
                          select new ProcessObject
                          {
                              Id = process.Id,
                              MainWindowTitle = process.MainWindowTitle,
                              PagedMemorySize = process.PagedMemorySize64,
                              PagedSystemMemorySize = process.PagedSystemMemorySize64,
                              PrivateMemorySize = process.PrivateMemorySize64,
                              ProcessName = process.ProcessName,
                              Running = process.Responding,
                              SessionId = process.SessionId,
                              VirtualMemorySize = process.VirtualMemorySize64,
                              PhysicalMemorySize = process.WorkingSet64
                          }).ToArray<ProcessObject>();
            }
            catch (Exception ex)
            {
                throw new FaultException<Fault>(Fault.CreateFromException(ex), Fault.CreateFaultReason(ex));
            }
            return result;
        }

        // Token: 0x06000008 RID: 8 RVA: 0x000022B0 File Offset: 0x000004B0
        [OperationBehavior(Impersonation = ImpersonationOption.Required)]
        public ProcessSecurityObject GetProcessSecurity(int processId)
        {
            ProcessSecurityObject result;
            try
            {
                string name = "Someone";
                string primarySid = "1234";
                GroupObject[] groups = new GroupObject[0];
                List<Privilege> privileges = new List<Privilege>();

                result = new ProcessSecurityObject
                {
                    Name = name,
                    PrimarySid = primarySid,
                    Groups = groups,
                    Privileges = privileges
                };
            }
            catch (Exception ex)
            {
                throw new FaultException<Fault>(Fault.CreateFromException(ex), Fault.CreateFaultReason(ex));
            }
            return result;
        }
    }
}
