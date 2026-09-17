using Microsoft.AspNetCore.Identity;

namespace User.Mgmt.Service.Models.Authentication.UserResponse
{
    public class CreateUserReponseDto
    {
        public string? Token { get; set; }

        public IdentityUser? User { get; set; }

        public bool IsSuccess { get; set; }
    }
}
