using Microsoft.AspNetCore.Identity;
using User.Mgmt.Service.Models;
using User.Mgmt.Service.Models.Authentication.Login;
using User.Mgmt.Service.Models.Authentication.SignUp;
using User.Mgmt.Service.Models.Authentication.UserResponse;

namespace User.Mgmt.Service.Services
{
    public interface IUserMgmtService
    {
        Task<APIResponse<CreateUserReponseDto>> CreateUserWithTokenAsnyc(RegisterUserDto registerUserDto);
        Task<APIResponse<List<string>>> AssignRoleToUserAsync(List<string> roles, IdentityUser user);
        Task<APIResponse<LoginOTPResponseDto>> GetOTPByLoginAsync(LoginRequestDto loginRequestDto);
    }
}
