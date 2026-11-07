using User.Mgmt.Service.Helpers;
using IDatabase = StackExchange.Redis.IDatabase;

namespace User.Mgmt.Service.Services
{
    public class RedisCacheService : IRedisCacheService
    {
        private readonly IDatabase _database;
        public RedisCacheService()
        {
            _database = ConnectionHelper.Connection.GetDatabase();
        }
        public T GetData<T>(string key)
        {
           var value = _database.StringGet(key);

            if (value.IsNullOrEmpty is false)
            {
                return System.Text.Json.JsonSerializer.Deserialize<T>(value!)!;
            }

            return default(T)!;
        }

        public object RemoveData(string key)
        {
            bool isKeyExists = _database.KeyExists(key);

            if (isKeyExists is true)
            {
                bool isKeyRemoved = _database.KeyDelete(key);

                if (isKeyRemoved is true)
                {
                    return new { Success = true, Message = $"Key '{key}' removed successfully." };
                }
                else
                {
                    return new { Success = false, Message = $"Failed to remove key '{key}'." };
                }
            }
            else
            {
                return new { Success = false, Message = $"Key '{key}' does not exist." };
            }
        }

        public bool SetData<T>(string key, T value, DateTimeOffset expirationTime)
        {
            TimeSpan expiration = expirationTime.DateTime.Subtract(DateTimeOffset.Now.DateTime);
            var isDataSet = _database.StringSet(key, System.Text.Json.JsonSerializer.Serialize(value), expiration);  

            if (isDataSet is true)
            {
                return true;
            }
            return false;
        }
    }
}
