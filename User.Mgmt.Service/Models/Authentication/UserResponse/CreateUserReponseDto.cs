using UserMgmt.Data.Models;

namespace User.Mgmt.Service.Models.Authentication.UserResponse
{
    public class CreateUserReponseDto
    {
        public string? Token { get; set; }

        public ApplicationUserDto? User { get; set; }

        public bool IsSuccess { get; set; }
    }
}
