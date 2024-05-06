using Microsoft.Extensions.Logging.Configuration;
using Microsoft.Extensions.Logging.EventLog;
using QueueRunner.Contract;

namespace QueueRunner.WebServer
{
    public class Program
    {
        public static void Main(string[] args)
        {
            Configuration.Load();

            var builder = WebApplication.CreateBuilder();
            LoggerProviderOptions.RegisterProviderOptions<EventLogSettings, EventLogLoggerProvider>(builder.Services);
            builder.Services.AddWindowsService(options =>
            {
                options.ServiceName = "Diagnostics Queue Web Server Service";
            });
            builder.Configuration.SetBasePath(AppDomain.CurrentDomain.BaseDirectory).AddJsonFile("appsettings.json");

            builder.Services.AddControllers();

            var app = builder.Build();


            app.UseDefaultFiles();
            app.UseStaticFiles();
            app.MapControllers();

            app.Run();
        }
    }
}