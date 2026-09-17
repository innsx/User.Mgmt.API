using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using User.Mgmt.API.Models;
using User.Mgmt.Service.Models;
using User.Mgmt.Service.Models.Authentication.Login;
using User.Mgmt.Service.Models.Authentication.SignUp;
using User.Mgmt.Service.Models.Authentication.UserResponse;

namespace User.Mgmt.Service.Services
{
    public class UserMgmtService : IUserMgmtService
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly SignInManager<IdentityUser> _signInManager;

        public UserMgmtService(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager, SignInManager<IdentityUser> signInManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _signInManager = signInManager;
        }

        public async Task<APIResponse<List<string>>> AssignRoleToUserAsync(List<string> roles, IdentityUser user)
        {
            var assignedRoles = new List<string>();

            foreach (var role in roles)
            {
                if (await _roleManager.RoleExistsAsync(role) is true)
                {
                    if (await _userManager.IsInRoleAsync(user, role) is false)
                    {
                        await _userManager.AddToRoleAsync(user, role);

                        assignedRoles.Add(role);
                    }
                }
            }

            return new APIResponse<List<string>>
            {
                IsSuccess = true,
                StatusCode = 200,
                Message = "Role has been assigned.",
                Response = assignedRoles
            };
        }

        public async Task<APIResponse<CreateUserReponseDto>> CreateUserWithTokenAsnyc(RegisterUserDto registerUserDto)
        {
            //check user exists in DB
            var userExists = await _userManager.FindByEmailAsync(registerUserDto.Email);

            if (userExists is not null)
            {
                return new APIResponse<CreateUserReponseDto>
                {
                    IsSuccess = false,
                    StatusCode = 403,
                    Message = "User already exits."
                };
            }

            // instantiate an IdentityUser; assign registerUserDto values to its properties
            IdentityUser user = new()
            {
                Email = registerUserDto.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = registerUserDto.Username,
                TwoFactorEnabled = true
            };


            var createUser = await _userManager.CreateAsync(user, registerUserDto.Password);

            if (createUser.Succeeded)
            {
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);

                return new APIResponse<CreateUserReponseDto>
                {
                    IsSuccess = true,
                    StatusCode = 201,
                    Message = "User created.",
                    Response = new CreateUserReponseDto() { Token = token, User = user }
                };
            }
            else
            {
                return new APIResponse<CreateUserReponseDto>
                {
                    IsSuccess = false,
                    StatusCode = 500,
                    Message = $"Failed to register User."
                };
            }
        }

        public async Task<APIResponse<LoginOTPResponseDto>> GetOTPByLoginAsync(LoginRequestDto loginRequestDto)
        {
            //checking user exists
            var user = await _userManager.FindByNameAsync(loginRequestDto.Username);

            if (user is not null)
            {
                //first sign-out current user
                await _signInManager.SignOutAsync();

                //re-sign-in User with loginRequestDto.Password
                await _signInManager.PasswordSignInAsync(
                    user,
                    loginRequestDto.Password,
                    false,
                    true
                );

                if (user.TwoFactorEnabled is true)
                {
                    var twoFToken = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");

                    return new APIResponse<LoginOTPResponseDto>
                    {
                        StatusCode = 200,
                        Message = $"OTP Two factor Authentication is not enabled.",
                        IsSuccess = true,
                        Response = new LoginOTPResponseDto()
                        {
                            User = user,
                            Token = twoFToken,
                            IsTwoFactorEnable = user.TwoFactorEnabled
                        }
                    };
                }
                else
                {
                    return new APIResponse<LoginOTPResponseDto>
                    {
                        StatusCode = 200,
                        Message = $"OTP Two factor Authentication is not enabled.",
                        IsSuccess = true,
                        Response = new LoginOTPResponseDto()
                        {
                            User = user,
                            Token = string.Empty,
                            IsTwoFactorEnable = user.TwoFactorEnabled
                        }
                    };
                }
            }
            else
            {
                return new APIResponse<LoginOTPResponseDto>
                {
                    StatusCode = 404,
                    Message = $"User is not found.",
                    IsSuccess = false
                };
            }
        }
    }
}
