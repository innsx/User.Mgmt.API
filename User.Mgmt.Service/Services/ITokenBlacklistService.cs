using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace User.Mgmt.Service.Services
{
    public interface ITokenBlacklistService
    {
        Task BlacklistTokenAsync(JwtSecurityToken token);
        Task<bool> IsTokenBlacklistedAsync(string jti);
        
    }
}
