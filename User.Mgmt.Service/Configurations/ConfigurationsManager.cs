using Microsoft.Extensions.Configuration;

namespace User.Mgmt.API.Configurations
{
    public class ConfigurationsManager
    {
        public static IConfiguration AppSettings { get; }

        static ConfigurationsManager()
        {
            AppSettings = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
                .Build();
        }
    }
}
