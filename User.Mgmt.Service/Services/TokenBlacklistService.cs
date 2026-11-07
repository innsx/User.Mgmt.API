using Microsoft.AspNetCore.Http;
using StackExchange.Redis;
using System.IdentityModel.Tokens.Jwt;
using IDatabase = StackExchange.Redis.IDatabase;

namespace User.Mgmt.Service.Services
{
    public class TokenBlacklistService : ITokenBlacklistService
    {
        private readonly IDatabase _redisDb;

        public TokenBlacklistService(IConnectionMultiplexer redis)
        {
            _redisDb = redis.GetDatabase();
        }

        public async Task BlacklistTokenAsync(JwtSecurityToken jwtToken)
        {
            //var tokenHandler = new JwtSecurityTokenHandler();

            //var canReadToken = tokenHandler.CanReadToken(token);
            //if (canReadToken is false)
            //    return;

            //var jwtToken = tokenHandler.ReadJwtToken(token);
            //var jti = jwtToken.Id; // Extracts the unique 'jti' claim

            //if (string.IsNullOrEmpty(jti))
            //    return;

            //Calculate how much time is left before the token expires naturally
            var expiryTime = jwtToken.ValidTo;
            var expiryRemainingTime = (expiryTime - DateTime.UtcNow);

            if (expiryRemainingTime > TimeSpan.Zero)
            {
                // Store in Redis with an absolute expiration
                RedisKey redisKey = $"blacklist:{jwtToken.Id}";
                RedisValue redisValue = "revoked";
                await _redisDb.StringSetAsync(redisKey, redisValue, expiryRemainingTime);
            }
        }

        public async Task<bool> IsTokenBlacklistedAsync(string token)
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            if (tokenHandler.CanReadToken(token) is false) 
                return false;

            var jwtToken = tokenHandler.ReadJwtToken(token);
            var jti = jwtToken.Id;

            if (string.IsNullOrEmpty(jti) is true) 
                return false;

            // Check if the JTI exists in the Redis blacklist cache
            var isBlacklisted = await _redisDb.KeyExistsAsync($"blacklist:{jti}");
            
            return isBlacklisted;
        }
    }   
}




//    public async Task BlacklistTokenAsync(string jti, TimeSpan expiryTime)
//    {
//        // Store the JTI as the key; the value can simply be "revoked"
//        // TTL ensures auto-cleanup from Redis cache
//        await _redisDb.StringSetAsync($"blacklist:{jti}", "revoked", expiryTime);
//    }

//    public async Task<bool> IsTokenBlacklistedAsync(string jti)
//    {
//        if (string.IsNullOrEmpty(jti))
//            return false;
//        return await _redisDb.KeyExistsAsync($"blacklist:{jti}");
//    }
//}