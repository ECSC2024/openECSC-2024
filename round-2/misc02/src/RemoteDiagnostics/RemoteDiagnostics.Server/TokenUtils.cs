using RemoteDiagnostics.Contract;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using static RemoteDiagnostics.Server.NativeMethods;

namespace RemoteDiagnostics.Server
{
    internal class TokenUtils
    {
        internal static string GetPrivilegeName(Luid luid)
        {
            uint nameLen = 0;
            LookupPrivilegeName(null, ref luid, null, ref nameLen);

            StringBuilder name = new StringBuilder((int)(nameLen + 1));
            if (!LookupPrivilegeName(null, ref luid, name, ref nameLen))
                throw new Win32Exception("LookupPrivilegeName() failed");

            return name.ToString();
        }

        internal static List<Privilege> GetTokenPrivileges(SafeNativeHandle hToken)
        {
            using (SafeMemoryBuffer tokenInfo = GetTokenInformation(hToken,
                TokenInformationClass.TokenPrivileges))
            {
                TOKEN_PRIVILEGES tokenPrivs = (TOKEN_PRIVILEGES)Marshal.PtrToStructure(
                    tokenInfo.DangerousGetHandle(),
                    typeof(TOKEN_PRIVILEGES));

                LUID_AND_ATTRIBUTES[] luidAttrs =
                    new LUID_AND_ATTRIBUTES[tokenPrivs.PrivilegeCount];
                PtrToStructureArray(luidAttrs, IntPtr.Add(tokenInfo.DangerousGetHandle(),
                    Marshal.SizeOf(tokenPrivs.PrivilegeCount)));

                return luidAttrs.Select(la => ToPrivilege(la)).ToList();
            }
        }

        internal static SafeNativeHandle OpenProcessToken(SafeNativeHandle hProcess, TokenAccessLevels access)
        {
            SafeNativeHandle hToken;
            if (!NativeMethods.OpenProcessToken(hProcess, access, out hToken))
                throw new Win32Exception(String.Format("Failed to open process token with access {0}",
                    access.ToString()));

            return hToken;
        }

        private static SafeMemoryBuffer GetTokenInformation(SafeNativeHandle hToken,
            TokenInformationClass infoClass)
        {
            bool res = NativeMethods.GetTokenInformation(hToken, infoClass, new SafeMemoryBuffer(IntPtr.Zero), 0,
                out uint tokenLength);
            int errCode = Marshal.GetLastWin32Error();
            if (!res && errCode != 24 && errCode != 122)  // ERROR_INSUFFICIENT_BUFFER, ERROR_BAD_LENGTH
                throw new Win32Exception(errCode, String.Format("GetTokenInformation({0}) failed to get buffer length",
                    infoClass.ToString()));

            SafeMemoryBuffer tokenInfo = new SafeMemoryBuffer((int)tokenLength);
            if (!NativeMethods.GetTokenInformation(hToken, infoClass, tokenInfo, tokenLength, out tokenLength))
                throw new Win32Exception(String.Format("GetTokenInformation({0}) failed", infoClass.ToString()));

            return tokenInfo;
        }

        private static void PtrToStructureArray<T>(T[] array, IntPtr ptr)
        {
            IntPtr ptrOffset = ptr;
            for (int i = 0; i < array.Length; i++, ptrOffset = IntPtr.Add(ptrOffset, Marshal.SizeOf(typeof(T))))
                array[i] = (T)Marshal.PtrToStructure(ptrOffset, typeof(T));
        }
    }
}
