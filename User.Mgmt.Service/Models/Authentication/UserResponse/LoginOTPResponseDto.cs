using Microsoft.AspNetCore.Identity;

namespace User.Mgmt.Service.Models.Authentication.UserResponse
{
    public class LoginOTPResponseDto
    {
        public string Token { get; set; } = null!;
        public bool IsTwoFactorEnable { get; set; }
        public IdentityUser User { get; set; } = null!;
    }
}
