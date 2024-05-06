using System;
using System.Windows.Forms;

namespace RemoteDiagnostics.Client
{
    internal static class Program
    {
        public static Connect connectWindow = null;
        public static string host = null;
        public static string username = null;
        public static string password = null;
        public static bool simulation = false;

        [STAThread]
        static void Main()
        {
            host = Environment.GetEnvironmentVariable("DHost");
            username = Environment.GetEnvironmentVariable("DUser");
            password = Environment.GetEnvironmentVariable("DPass");
            if (host != null) simulation = true;

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            connectWindow = new Connect();
            Application.Run(connectWindow);
        }
    }
}
