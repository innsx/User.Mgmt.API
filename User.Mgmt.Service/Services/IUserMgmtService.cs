using User.Mgmt.Service.Models;
using User.Mgmt.Service.Models.Authentication.Login;
using User.Mgmt.Service.Models.Authentication.SignUp;
using User.Mgmt.Service.Models.Authentication.UserResponse;
using UserMgmt.Data.Models;

namespace User.Mgmt.Service.Services
{
    public interface IUserMgmtService
    {
        Task<APIResponseDto<CreateUserReponseDto>> CreateUserWithTokenAsnyc(RegisterUserDto registerUserDto);
        Task<APIResponseDto<List<string>>> AssignRoleToUserAsync(List<string> roles, ApplicationUserDto user);
        Task<APIResponseDto<LoginUser2FTokenResponseDto>> GetOTPByLoginAsync(LoginRequestDto loginRequestDto);
        Task<APIResponseDto<LoginResponseDto>> GetJwtTokenAsync(ApplicationUserDto user);
        Task<APIResponseDto<LoginResponseDto>> LoginUserWith2FTokenAsnyc(string twoFToken, string userName);
        Task<APIResponseDto<LoginResponseDto>> RenewAccessTokenAsync(LoginResponseDto token);
    }
}
