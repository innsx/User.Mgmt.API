using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using User.Mgmt.Service.Models;
using User.Mgmt.Service.Models.Authentication.Login;
using User.Mgmt.Service.Models.Authentication.SignUp;
using User.Mgmt.Service.Models.Authentication.UserResponse;
using UserMgmt.Data.Models;

namespace User.Mgmt.Service.Services
{
    public class UserMgmtService : IUserMgmtService
    {
        private readonly UserManager<ApplicationUserDto> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly SignInManager<ApplicationUserDto> _signInManager;
        private readonly IConfiguration _configuration;

        public UserMgmtService(UserManager<ApplicationUserDto> userManager, RoleManager<IdentityRole> roleManager, SignInManager<ApplicationUserDto> signInManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _signInManager = signInManager;
            _configuration = configuration;
        }

        public async Task<APIResponseDto<List<string>>> AssignRoleToUserAsync(List<string> roles, ApplicationUserDto user)
        {
            var assignedRoles = new List<string>();

            var isNullEmpty = string.IsNullOrEmpty(roles.ToString());

            if (roles.Count > 0 && isNullEmpty is false)
            {
                foreach (var role in roles)
                {
                    if (await _roleManager.RoleExistsAsync(role) is true)
                    {
                        if (await _userManager.IsInRoleAsync(user, role) is false)
                        {
                            await _userManager.AddToRoleAsync(user, role);

                            assignedRoles.Add(role);

                            return new APIResponseDto<List<string>>
                            {
                                IsSuccess = true,
                                StatusCode = 200,
                                Message = "Role has been assigned.",
                                Response = assignedRoles
                            };
                        }

                        return new APIResponseDto<List<string>>
                        {
                            IsSuccess = false,
                            StatusCode = 204,
                            Message = "User already assigned to this Role."
                        };
                    }
                }
            }

            var defaultRole = "Guest";

            if (await _roleManager.RoleExistsAsync(defaultRole) is true)
            {
                if (await _userManager.IsInRoleAsync(user, defaultRole) is false)
                {
                    await _userManager.AddToRoleAsync(user, defaultRole);

                    assignedRoles.Add(defaultRole);
                }
            }

            return new APIResponseDto<List<string>>
            {
                IsSuccess = true,
                StatusCode = 200,
                Message = "A Default \'Guest\' Role has been assigned.",
                Response = assignedRoles
            };
        }

        public async Task<APIResponseDto<CreateUserReponseDto>> CreateUserWithTokenAsnyc(RegisterUserDto registerUserDto)
        {
            //check user exists in DB
            var userExists = await _userManager.FindByEmailAsync(registerUserDto.Email);

            if (userExists is not null)
            {
                return new APIResponseDto<CreateUserReponseDto>
                {
                    IsSuccess = false,
                    StatusCode = 403,
                    Message = "User already exits."
                };
            }

            // instantiate an ApplicationUserDto;
            ApplicationUserDto user = new()
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

                return new APIResponseDto<CreateUserReponseDto>
                {
                    IsSuccess = true,
                    StatusCode = 201,
                    Message = "User created.",
                    Response = new CreateUserReponseDto()
                    {
                        Token = token,
                        User = user
                    }
                };
            }
            else
            {
                return new APIResponseDto<CreateUserReponseDto>
                {
                    IsSuccess = false,
                    StatusCode = 500,
                    Message = $"Failed to register User."
                };
            }
        }

        public async Task<APIResponseDto<JwtTokenResponseDto>> GetJwtTokenAsync(ApplicationUserDto user)
        {
            List<Claim> authClaims = await CreateClaimsAsnyc(user);

            var accessJwtToken = GenerateToken(authClaims);

            if (accessJwtToken is not null)
            {
                return new APIResponseDto<JwtTokenResponseDto>
                {
                    IsSuccess = true,
                    StatusCode = 200,
                    Message = "Successfully generated an Access Token.",
                    Response = new JwtTokenResponseDto()
                    {
                        TokenContext = new JwtSecurityTokenHandler().WriteToken(accessJwtToken),
                        ExpiryTokenDate = accessJwtToken.ValidTo,
                    }
                };
            }

            return new APIResponseDto<JwtTokenResponseDto>
            {
                IsSuccess = false,
                StatusCode = 404,
                Message = "Failed to generated an Access Token.",
            };
        }

        private async Task<List<Claim>> CreateClaimsAsnyc(ApplicationUserDto user)
        {
            var authClaims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var userRoles = await _userManager.GetRolesAsync(user);

            if (userRoles.Any())
            {
                foreach (var role in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, role));
                }

                return authClaims;
            }
            else
            {
                return authClaims;
            }
        }

        public async Task<APIResponseDto<LoginOTPResponseDto>> GetOTPByLoginAsync(LoginRequestDto loginRequestDto)
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

                    return new APIResponseDto<LoginOTPResponseDto>
                    {
                        StatusCode = 200,
                        Message = $"OTP Two factor Authentication is not enabled.",
                        IsSuccess = true,
                        Response = new LoginOTPResponseDto()
                        {
                            User = user,
                            TwoFToken = twoFToken,
                            IsTwoFactorEnable = user.TwoFactorEnabled
                        }
                    };
                }
                else
                {
                    return new APIResponseDto<LoginOTPResponseDto>
                    {
                        StatusCode = 200,
                        Message = $"OTP Two factor Authentication is not enabled.",
                        IsSuccess = true,
                        Response = new LoginOTPResponseDto()
                        {
                            User = user,
                            TwoFToken = string.Empty,
                            IsTwoFactorEnable = user.TwoFactorEnabled
                        }
                    };
                }
            }
            else
            {
                return new APIResponseDto<LoginOTPResponseDto>
                {
                    StatusCode = 404,
                    Message = $"User not found.",
                    IsSuccess = false
                };
            }
        }

        private JwtSecurityToken GenerateToken(List<Claim> authClaims)
        {
            var secretKey = Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]);
            var authSigningKey = new SymmetricSecurityKey(secretKey);
            _ = int.TryParse(_configuration["JWT:TokenValidationInMinutes"], out int tokenValidationInMinutes);

            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: DateTime.Now.AddMinutes(tokenValidationInMinutes),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
            );

            return token;
        }
    }
}
