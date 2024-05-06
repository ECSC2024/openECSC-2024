using Microsoft.Win32.SafeHandles;
using RemoteDiagnostics.Contract;
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace RemoteDiagnostics.Server
{
    internal class NativeMethods
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct Luid
        {
            public uint LowPart;
            public int HighPart;

            public static explicit operator ulong(Luid l)
            {
                return (ulong)l.HighPart << 32 | l.LowPart;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID_AND_ATTRIBUTES
        {
            public Luid Luid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_PRIVILEGES
        {
            public uint PrivilegeCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public LUID_AND_ATTRIBUTES[] Privileges;
        }

        internal static Privilege ToPrivilege(LUID_AND_ATTRIBUTES la)
        {
            return new Privilege
            {
                Name = TokenUtils.GetPrivilegeName(la.Luid),
                Attributes = (PrivilegeAttributes)la.Attributes
            };
        }

        public enum TokenInformationClass : uint
        {
            TokenUser = 1,
            TokenPrivileges = 3,
            TokenStatistics = 10,
            TokenElevationType = 18,
            TokenLinkedToken = 19,
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(
            IntPtr Handle);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool GetTokenInformation(
            SafeNativeHandle TokenHandle,
            TokenInformationClass TokenInformationClass,
            SafeMemoryBuffer TokenInformation,
            uint TokenInformationLength,
            out uint ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool LookupPrivilegeName(
            string SystemName,
            ref Luid Luid,
            StringBuilder Name,
            ref uint NameSize);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool OpenProcessToken(
            SafeNativeHandle ProcessHandle,
            TokenAccessLevels DesiredAccess,
            out SafeNativeHandle TokenHandle);

        internal class SafeMemoryBuffer : SafeHandleZeroOrMinusOneIsInvalid
        {
            public SafeMemoryBuffer() : base(true) { }
            public SafeMemoryBuffer(int cb) : base(true)
            {
                SetHandle(Marshal.AllocHGlobal(cb));
            }
            public SafeMemoryBuffer(IntPtr handle) : base(true)
            {
                SetHandle(handle);
            }

            protected override bool ReleaseHandle()
            {
                Marshal.FreeHGlobal(handle);
                return true;
            }
        }

        internal class SafeNativeHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            public SafeNativeHandle() : base(true) { }
            public SafeNativeHandle(IntPtr handle) : base(true) { this.handle = handle; }

            protected override bool ReleaseHandle()
            {
                return CloseHandle(handle);
            }
        }
    }
}
