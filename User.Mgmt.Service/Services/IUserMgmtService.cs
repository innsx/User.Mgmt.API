using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
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
        Task<ApplicationUser> GetUserAsync(LoginRequestDto loginRequestDto);
        Task<ResponseDto> CheckPasswordSigninAsync(LoginRequestDto loginRequestDto, ApplicationUser user);
        Message GeneratesEmailMessageWith2FToken(APIResponseDto<LoginUser2FTokenResponseDto> generates2FTokenResponse);
        Task<APIResponseDto<LoginUser2FTokenResponseDto>> Generates2FTokenAsync(LoginRequestDto loginRequestDto);
        Task UserLogoutAsync();
        Task<APIResponseDto<LoginTokensResponseDto>> GeneratesAccessNRefreshTokensAsync(ApplicationUser user);
        Task<APIResponseDto<LoginTokensResponseDto>> ValidatesLoginUser2FTokenAsnyc(string twoFToken, string userName);
        Task<APIResponseDto<LoginTokensResponseDto>> RenewAccessNRefreshTokensAsync(LoginTokensResponseDto token);

        //APIResponseDto<LoginTokensResponseDto> EmailConfirmationLink(Func<string, string, Task<IActionResult>> emailRegisteredUserConfirm, RegisterUserRequestDto registerUserDto, APIResponseDto<CreateUserReponseDto> createdUserResponse);
        Task<ResponseDto> GetPasswordResetTokenAsync(PasswordResetRequestDto passwordResetRequestDto);
    }
}
