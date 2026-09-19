using User.Mgmt.Service.Models;
using User.Mgmt.Service.Models.Authentication.Login;
using User.Mgmt.Service.Models.Authentication.SignUp;
using User.Mgmt.Service.Models.Authentication.UserResponse;
using UserMgmt.Data.Models;

namespace User.Mgmt.Service.Services
{
    public interface IUserMgmtService
    {
        Task<APIResponseDto<CreateUserReponseDto>> CreateUserWithTokenAsnyc(RegisterUserRequestDto registerUserDto);
        Task<APIResponseDto<List<string>>> AssignRoleToUserAsync(List<string> roles, ApplicationUser user);
        Task<APIResponseDto<LoginUser2FTokenResponseDto>> Generate2FTokenAsync(LoginRequestDto loginRequestDto);
        Task<APIResponseDto<LoginTokensResponseDto>> GenerateAccessJwtTokenAsync(ApplicationUser user);
        Task<APIResponseDto<LoginTokensResponseDto>> LoginUserWith2FTokenAsnyc(string twoFToken, string userName);
        Task<APIResponseDto<LoginTokensResponseDto>> RenewAccessJwtTokenAsync(LoginTokensResponseDto token);
    }
}
