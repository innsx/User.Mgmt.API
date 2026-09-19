using Microsoft.AspNetCore.Identity;

namespace UserMgmt.Data.Models
{
    public class ApplicationUser : IdentityUser
    {
        public string RefreshToken { get; set; } = string.Empty;
        public DateTime RefreshTokenExpiry { get; set; }
    }
}
