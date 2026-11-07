using User.Mgmt.API.Configurations;
using StackExchange.Redis;


namespace User.Mgmt.Service.Helpers
{
    public class ConnectionHelper
    {
        private static Lazy<ConnectionMultiplexer> lazyConn;

        static ConnectionHelper()
        {
            lazyConn = new Lazy<ConnectionMultiplexer>(() =>
            {
                return ConnectionMultiplexer.Connect(ConfigurationsManager.AppSettings["RedisDbConn"]);
            });
        }

        public static ConnectionMultiplexer Connection
        {
            get             
            {
                return lazyConn.Value;
            }
        }
    }
}