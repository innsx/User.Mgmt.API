using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using User.Mgmt.API.Models;
using User.Mgmt.Data.Models;
using User.Mgmt.Service.Models;
using User.Mgmt.Service.Models.Authentication.Login;
using User.Mgmt.Service.Models.Authentication.SignUp;
using User.Mgmt.Service.Models.Authentication.UserResponse;

namespace User.Mgmt.Service.Services
{
    public interface IUserMgmtService
    {
        Task<APIResponseDto<CreateUserReponseDto>> CreatesRegisterUserAsnyc(RegisterUserRequestDto registerUserDto);
        Task<APIResponseDto<List<string>>> AssignsRoleToUserAsync(List<string> roles, ApplicationUser user);
        Task<APIResponseDto<LoginTokensResponseDto>> ValidatesRegistrationTokenAsync(string token, string email);
        Task<APIResponseDto<LoginUser2FTokenResponseDto>> Generates2FTokenAsync(LoginRequestDto loginRequestDto);
        Task<APIResponseDto<LoginTokensResponseDto>> GeneratesAccessNRefreshTokensAsync(ApplicationUser user);
        Task<APIResponseDto<LoginTokensResponseDto>> ValidatesLoginUser2FTokenAsnyc(string twoFToken, string userName);
        Task<APIResponseDto<LoginTokensResponseDto>> RenewAccessNRefreshTokensAsync(LoginTokensResponseDto token);
        //APIResponseDto<LoginTokensResponseDto> EmailConfirmationLink(Func<string, string, Task<IActionResult>> emailRegisteredUserConfirm, RegisterUserRequestDto registerUserDto, APIResponseDto<CreateUserReponseDto> createdUserResponse);
        Task<ResponseDto> GetPasswordResetTokenAsync(PasswordResetRequestDto passwordResetRequestDto);
    }
}
