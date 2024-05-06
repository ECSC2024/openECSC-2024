using System;
using System.Net.Security;
using System.Net.Sockets;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace Client
{
    internal class Program
    {
        [DllImport("kernel32.dll")]
        public static extern IntPtr LoadLibrary(string dllToLoad);

        static TcpClient client = null;

        static void Main(string[] args)
        {
            IntPtr module = LoadLibrary(@"C:\Users\Administrator\Desktop\NegotiateStreamPOC02\x64\Release\SSPIHook.dll");
            if (module == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to load SSPIHook");
                return;
            }

            // Establish the remote endpoint for the socket.
            // For this example, use the local machine.
            NetworkCredential myCred = new NetworkCredential();

            IPAddress ipAddress = IPAddress.Parse("127.0.0.1");
            // Client and server use port 11000.
            IPEndPoint remoteEP = new IPEndPoint(ipAddress, 11000);
            // Create a TCP/IP socket.
            client = new TcpClient();
            // Connect the socket to the remote endpoint.
            client.Connect(remoteEP);
            Console.WriteLine("Client connected to {0}.", remoteEP.ToString());
            // Ensure the client does not close when there is
            // still data to be sent to the server.
            client.LingerState = new LingerOption(true, 0);
            // Request authentication.
            NetworkStream clientStream = client.GetStream();
            NegotiateStream authStream = new NegotiateStream(clientStream, false);
            // Pass the NegotiateStream as the AsyncState object
            // so that it is available to the callback delegate.
            Task authenticateTask = authStream
                .AuthenticateAsClientAsync(
                    myCred,
                    "localhost",
                    ProtectionLevel.None,
                    TokenImpersonationLevel.Impersonation)
                .ContinueWith(task =>
                {
                    Console.WriteLine("Client ending authentication...");
                    Console.WriteLine("ImpersonationLevel: {0}", authStream.ImpersonationLevel);
                });

            Console.WriteLine("Client waiting for authentication...");
            // Wait until the result is available.
            authenticateTask.Wait();
            // Display the properties of the authenticated stream.
            AuthenticatedStreamReporter.DisplayProperties(authStream);
            // Send a message to the server.
            // Encode the test data into a byte array.
            byte[] message = Encoding.UTF8.GetBytes("Hello from the client.");
            Task writeTask = authStream
                .WriteAsync(message, 0, message.Length)
                .ContinueWith(task =>
                {
                    Console.WriteLine("Client ending write operation...");
                });

            writeTask.Wait();
            Console.WriteLine("Sent {0} bytes.", message.Length);
            // Close the client connection.
            authStream.Close();
            Console.WriteLine("Client closed.");
        }
    }

    // The following class displays the properties of an authenticatedStream.
    public class AuthenticatedStreamReporter
    {
        public static void DisplayProperties(AuthenticatedStream stream)
        {
            Console.WriteLine("IsAuthenticated: {0}", stream.IsAuthenticated);
            Console.WriteLine("IsMutuallyAuthenticated: {0}", stream.IsMutuallyAuthenticated);
            Console.WriteLine("IsEncrypted: {0}", stream.IsEncrypted);
            Console.WriteLine("IsSigned: {0}", stream.IsSigned);
            Console.WriteLine("IsServer: {0}", stream.IsServer);
        }
    }
}
