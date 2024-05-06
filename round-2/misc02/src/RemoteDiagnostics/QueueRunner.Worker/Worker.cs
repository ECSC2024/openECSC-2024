using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using QueueRunner.Contract;

namespace QueueRunner.Worker
{
    public class Worker : BackgroundService
    {
        private readonly ILogger<Worker> _logger;
        private static readonly string flag = File.ReadAllText(@"C:\RemoteDiagnostics\flag.txt");

        public Worker(ILogger<Worker> logger)
        {
            _logger = logger;
        }

        private static readonly Random random = new();

        private static string GenerateRandomString(int length)
        {
            const string chars = "abcdef0123456789";
            StringBuilder sb = new StringBuilder(length);

            for (int i = 0; i < length; i++)
            {
                sb.Append(chars[random.Next(chars.Length)]);
            }

            return sb.ToString();
        }

        private static string GetTmpDirectory()
        {
            string tmpDirectory;

            do
            {
                tmpDirectory = Path.Combine(Path.GetTempPath(), Path.GetFileNameWithoutExtension(Path.GetRandomFileName()));
            } while (Directory.Exists(tmpDirectory));

            Directory.CreateDirectory(tmpDirectory);

            DirectoryInfo dInfo = new(tmpDirectory);
            DirectorySecurity dSecurity = dInfo.GetAccessControl();
            dSecurity.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null), FileSystemRights.Read | FileSystemRights.ReadData, InheritanceFlags.ObjectInherit | InheritanceFlags.ContainerInherit, PropagationFlags.InheritOnly, AccessControlType.Allow));
            dInfo.SetAccessControl(dSecurity);

            return tmpDirectory;
        }

        private static void WriteTmpFlag(string tmpDir)
        {
            string tmpFlag = flag.Trim();
            tmpFlag = flag.Replace("}", string.Format("_{0}}}", GenerateRandomString(8)));
            File.WriteAllText(Path.Combine(tmpDir, "flag.txt"), tmpFlag);
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            var workers = new List<Task>();
            for (int i = 0; i < Configuration.Workers; i++)
                workers.Add(WorkerThread(i, stoppingToken));

            await Task.WhenAll(workers.ToArray());
        }

        internal async Task WorkerThread(int id, CancellationToken stoppingToken)
        {
            var tcs = new TaskCompletionSource<bool>();
            stoppingToken.Register(() =>
                tcs.TrySetCanceled(), useSynchronizationContext: false);
            var cancellationTask = tcs.Task;

            while (!stoppingToken.IsCancellationRequested)
            {
                _logger.LogInformation("Worker running at: {time}", DateTimeOffset.Now);

                var queueTask = Queue.Receive();

                var readyTask = await Task.WhenAny(queueTask, cancellationTask);

                if (readyTask == cancellationTask)
                {
                    break;
                }

                QueueItem queueItem = await queueTask;

                var tmpDir = GetTmpDirectory();
                WriteTmpFlag(tmpDir);

                _logger.LogInformation("Spawning container: {id} - {endpoint} - {tmpFlag}", queueItem.Id, queueItem.Endpoint, tmpDir);

                var containerId = GenerateRandomString(8);


                // docker run --dns 8.8.8.8 --rm -d -v C:\tmpdir_withflag:C:\flag:ro --name diagnostics-{id} -e "DHost={endpoint}" -e "DUser=<randomusername>" -e "DPass=<randompassword>" diagnostics
                var process = Process.Start(new ProcessStartInfo
                {
                    FileName = Configuration.Docker,
                    ArgumentList = {
                        "-H",
                        "npipe:////./pipe/docker",
                        "run",
                        "--dns",
                        "8.8.8.8",
                        "--rm",
                        "-d",
                        "-v",
                        string.Format(@"{0}:C:\flag:ro", tmpDir),
                        "--name",
                        string.Format("diagnostics-{0}", containerId),
                        "-e",
                        string.Format("DHost={0}", queueItem.Endpoint),
                        "-e",
                        string.Format("DUser={0}", GenerateRandomString(16)),
                        "-e",
                        string.Format("DPass={0}", GenerateRandomString(16)),
                        "diagnostics"
                    },
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                }) ?? throw new Exception("Process could not be created");

                await Task.Delay(Configuration.Runtime * 1000, stoppingToken);

                if (process.HasExited && process.ExitCode != 0)
                {
                    string error = process.StandardError.ReadToEnd();
                    _logger.LogCritical("Failed to spawn container: {error}", error);
                }

                // docker kill diagnostics-{id}
                Process.Start(new ProcessStartInfo
                {
                    FileName = Configuration.Docker,
                    ArgumentList = {
                        "-H",
                        "npipe:////./pipe/docker",
                        "kill",
                        string.Format("diagnostics-{0}", containerId)
                    },
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                });

                await Task.Delay(1000, stoppingToken);

                try
                {
                    Directory.Delete(tmpDir, true);
                }
                catch (Exception e)
                {
                    _logger.LogWarning("Failed to delete flag: {dir} - {error}", tmpDir, e.ToString());
                }

                _logger.LogInformation("Done");
            }
        }
    }
}