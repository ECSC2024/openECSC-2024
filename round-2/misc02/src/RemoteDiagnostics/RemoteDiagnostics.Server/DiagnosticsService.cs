using RemoteDiagnostics.Contract;
using System.IO;
using System;
using System.ServiceModel;
using System.Security.Claims;
using System.Security.Principal;
using System.Net.NetworkInformation;
using System.Linq;
using System.Diagnostics;
using System.Collections.Generic;
using static RemoteDiagnostics.Server.NativeMethods;
using static RemoteDiagnostics.Server.TokenUtils;

namespace RemoteDiagnostics.Server
{
    [ServiceBehavior(InstanceContextMode = InstanceContextMode.Single)]
    public class DiagnosticsService : IDiagnostics
    {
        public bool Ping()
        {
            return true;
        }

        [OperationBehavior(Impersonation = ImpersonationOption.Required)]
        public WhoAmIObject WhoAmI()
        {
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

        [OperationBehavior(Impersonation = ImpersonationOption.Required)]
        public DiskInformationObject GetDiskInformation()
        {
            try
            {
                return new DiskInformationObject
                {
                    Drives = DriveInfo.GetDrives(),
                };
            }
            catch (Exception ex)
            {
                throw new FaultException<Fault>(Fault.CreateFromException(ex), Fault.CreateFaultReason(ex));
            }
        }

        [OperationBehavior(Impersonation = ImpersonationOption.Required)]
        public DirectoryInformationObject GetDirectoryInformation(string path)
        {
            try
            {
                DirectoryInfo directoryInfo = new DirectoryInfo(path);

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
            catch (Exception ex)
            {
                throw new FaultException<Fault>(Fault.CreateFromException(ex), Fault.CreateFaultReason(ex));
            }
        }

        [OperationBehavior(Impersonation = ImpersonationOption.Required)]
        public HostInformationObject GetHostInformation()
        {
            try
            {
                return new HostInformationObject
                {
                    MachineName = Environment.MachineName,
                    OSVersion = Environment.OSVersion,
                    ProcessorCount = Environment.ProcessorCount,
                };
            }
            catch (Exception ex)
            {
                throw new FaultException<Fault>(Fault.CreateFromException(ex), Fault.CreateFaultReason(ex));
            }
        }

        [OperationBehavior(Impersonation = ImpersonationOption.Required)]
        public NetworkInformationObject GetNetworkInformation()
        {
            try
            {
                var Interfaces = NetworkInterface.GetAllNetworkInterfaces().Select(
                        ni =>
                        {
                            IPInterfaceProperties ifp = ni.GetIPProperties();
                            return new Interface
                            {
                                Name = ni.Name,
                                Description = ni.Description,
                                Status = ni.OperationalStatus,
                                DnsSuffix = ifp.DnsSuffix,
                                DnsAddresses = ifp.DnsAddresses.ToArray(),
                                UnicastAddresses = ifp.UnicastAddresses.Select(addr => new UnicastIPAddress
                                {
                                    PreferredLifetime = addr.AddressPreferredLifetime,
                                    ValidLifetime = addr.AddressValidLifetime,
                                    DhcpLeaseLifetime = addr.DhcpLeaseLifetime,
                                    IPv4Mask = addr.IPv4Mask,
                                    PrefixLength = addr.PrefixLength,
                                    Address = addr.Address,
                                }).ToArray(),
                                GatewayAddresses = ifp.GatewayAddresses.Select(addr => new GatewayIPAddress
                                {
                                    Address = addr.Address
                                }).ToArray(),
                                DhcpServerAddresses = ifp.DhcpServerAddresses.ToArray(),
                            };
                        }
                        ).ToArray();

                return new NetworkInformationObject
                {
                    Interfaces = NetworkInterface.GetAllNetworkInterfaces().Select(
                        ni =>
                        {
                            IPInterfaceProperties ifp = ni.GetIPProperties();
                            return new Interface
                            {
                                Name = ni.Name,
                                Description = ni.Description,
                                Status = ni.OperationalStatus,
                                DnsSuffix = ifp.DnsSuffix,
                                DnsAddresses = ifp.DnsAddresses.ToArray(),
                                UnicastAddresses = ifp.UnicastAddresses.Select(addr => new UnicastIPAddress
                                {
                                    PreferredLifetime = addr.AddressPreferredLifetime,
                                    ValidLifetime = addr.AddressValidLifetime,
                                    DhcpLeaseLifetime = addr.DhcpLeaseLifetime,
                                    IPv4Mask = addr.IPv4Mask,
                                    PrefixLength = addr.PrefixLength,
                                    Address = addr.Address,
                                }).ToArray(),
                                GatewayAddresses = ifp.GatewayAddresses.Select(addr => new GatewayIPAddress
                                {
                                    Address = addr.Address
                                }).ToArray(),
                                DhcpServerAddresses = ifp.DhcpServerAddresses.ToArray(),
                            };
                        }
                        ).ToArray()
                };
            }
            catch (Exception ex)
            {
                throw new FaultException<Fault>(Fault.CreateFromException(ex), Fault.CreateFaultReason(ex));
            }
        }

        [OperationBehavior(Impersonation = ImpersonationOption.Required)]
        public ProcessObject[] GetProcesses()
        {
            try
            {
                return Process.GetProcesses().Select(process =>
                {
                    return new ProcessObject
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
                        PhysicalMemorySize = process.WorkingSet64,
                    };
                }).ToArray();
            }
            catch (Exception ex)
            {
                throw new FaultException<Fault>(Fault.CreateFromException(ex), Fault.CreateFaultReason(ex));
            }
        }

        [OperationBehavior(Impersonation = ImpersonationOption.Required)]
        public ProcessSecurityObject GetProcessSecurity(int processId)
        {
            try
            {
                Process process = Process.GetProcessById(processId);
                SafeNativeHandle processHandle = OpenProcessToken(new SafeNativeHandle(process.Handle), TokenAccessLevels.Query);
                WindowsIdentity wi = new WindowsIdentity(processHandle.DangerousGetHandle());

                string name = wi.Name;
                string primarySid = Array.Find(wi.Claims.ToArray(), (Claim claim) => claim.Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/primarysid").Value;
                GroupObject[] groups = wi.Claims.Where(claim => claim.Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid").Select(claim =>
                {
                    SecurityIdentifier sid = new SecurityIdentifier(claim.Value);
                    return new GroupObject
                    {
                        Name = sid.Translate(typeof(NTAccount)).Value.ToString(),
                        Sid = sid.ToString()
                    };
                }).ToArray();
                List<Privilege> privileges = GetTokenPrivileges(processHandle);

                return new ProcessSecurityObject
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
        }
    }
}