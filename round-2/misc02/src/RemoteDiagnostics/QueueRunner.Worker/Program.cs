using Microsoft.Extensions.Logging.Configuration;
using Microsoft.Extensions.Logging.EventLog;
using QueueRunner.Contract;

namespace QueueRunner.Worker
{
    public class Program
    {
        public static void Main(string[] args)
        {
            Configuration.Load();

            var builder = Host.CreateDefaultBuilder(args)
                .ConfigureServices((hostContext, services) =>
                {
                    LoggerProviderOptions.RegisterProviderOptions<EventLogSettings, EventLogLoggerProvider>(services);
                    services.AddWindowsService(options =>
                     {
                         options.ServiceName = "Diagnostics Queue Worker Service";
                     });

                    services.AddHostedService<Worker>();
                })
                .ConfigureAppConfiguration(configuration =>
                {
                    configuration.SetBasePath(AppDomain.CurrentDomain.BaseDirectory).AddJsonFile("appsettings.json");
                });

            var host = builder.Build();
            host.Run();
        }
    }
}