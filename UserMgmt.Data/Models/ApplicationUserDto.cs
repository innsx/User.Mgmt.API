using Microsoft.AspNetCore.Identity;

namespace UserMgmt.Data.Models
{
    public class ApplicationUserDto : IdentityUser
    {
        public string RefreshToken { get; set; } = string.Empty;
        public DateTime RefreshTokenExpiry { get; set; }
    }
}
