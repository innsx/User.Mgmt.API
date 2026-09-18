using Microsoft.AspNetCore.Identity;
using UserMgmt.Data.Models;

namespace User.Mgmt.Service.Models.Authentication.UserResponse
{
    public class LoginUser2FTokenResponseDto
    {
        public string TwoFToken { get; set; } = null!;
        public bool IsTwoFactorEnable { get; set; }
        public ApplicationUserDto User { get; set; } = null!;
    }
}
