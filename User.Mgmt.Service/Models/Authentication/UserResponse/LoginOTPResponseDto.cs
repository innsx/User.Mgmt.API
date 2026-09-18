using Microsoft.AspNetCore.Identity;
using UserMgmt.Data.Models;

namespace User.Mgmt.Service.Models.Authentication.UserResponse
{
    public class LoginOTPResponseDto
    {
        public string TwoFToken { get; set; } = null!;
        public bool IsTwoFactorEnable { get; set; }
        public ApplicationUserDto User { get; set; } = null!;
    }
}
