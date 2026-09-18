using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
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

        public async Task<APIResponseDto<LoginResponseDto>> GetJwtTokenAsync(ApplicationUserDto user)
        {
            List<Claim> authClaims = await CreateClaimsAsnyc(user);

            var accessJwtToken = GenerateToken(authClaims);

            _ = int.TryParse(_configuration["JWT:RefreshTokenValidity"], out int refreshTokenValidity);

            user.RefreshToken = GenereateRefreshToken();
            user.RefreshTokenExpiry = DateTime.UtcNow.AddDays(refreshTokenValidity);

            await _userManager.UpdateAsync(user);

            return new APIResponseDto<LoginResponseDto>
            {
                IsSuccess = true,
                StatusCode = 200,
                Message = "Successfully generated Token.",
                Response = new LoginResponseDto()
                {
                    AccessToken = new JwtTokenTypeResponseDto
                    {
                        TokenContext = new JwtSecurityTokenHandler().WriteToken(accessJwtToken),
                        ExpiryTokenDate = accessJwtToken.ValidTo
                    },
                    RefreshToken = new JwtTokenTypeResponseDto
                    {
                        TokenContext = user.RefreshToken,
                        ExpiryTokenDate = user.RefreshTokenExpiry
                    }
                }
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

        private JwtSecurityToken GenerateToken(List<Claim> authClaims)
        {
            var secretKey = Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]);

            var authSigningKey = new SymmetricSecurityKey(secretKey);

            _ = int.TryParse(_configuration["JWT:TokenValidationInMinutes"], out int tokenValidationInMinutes);

            var expirationTimeUtc = DateTime.UtcNow.AddMinutes(tokenValidationInMinutes);

            var localTimeZone = TimeZoneInfo.Local;

            var expirationTimeInLocalTimeZone = TimeZoneInfo.ConvertTimeFromUtc(expirationTimeUtc, localTimeZone);

            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: expirationTimeInLocalTimeZone,
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
            );

            return token;
        }

        public async Task<APIResponseDto<LoginUser2FTokenResponseDto>> GetOTPByLoginAsync(LoginRequestDto loginRequestDto)
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

                    return new APIResponseDto<LoginUser2FTokenResponseDto>
                    {
                        StatusCode = 200,
                        Message = $"OTP Two factor Authentication is not enabled.",
                        IsSuccess = true,
                        Response = new LoginUser2FTokenResponseDto()
                        {
                            User = user,
                            TwoFToken = twoFToken,
                            IsTwoFactorEnable = user.TwoFactorEnabled
                        }
                    };
                }
                else
                {
                    return new APIResponseDto<LoginUser2FTokenResponseDto>
                    {
                        StatusCode = 200,
                        Message = $"OTP Two factor Authentication is not enabled.",
                        IsSuccess = true,
                        Response = new LoginUser2FTokenResponseDto()
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
                return new APIResponseDto<LoginUser2FTokenResponseDto>
                {
                    StatusCode = 404,
                    Message = $"User not found.",
                    IsSuccess = false
                };
            }
        }

        private string GenereateRefreshToken()
        {
            var randomNumber = new byte[64];
            var range = RandomNumberGenerator.Create();
            range.GetBytes(randomNumber);

            return Convert.ToBase64String(randomNumber);
        }

        public async Task<APIResponseDto<LoginResponseDto>> LoginUserWith2FTokenAsnyc(string twoFToken, string userName)
        {
            var user = await _userManager.FindByNameAsync(userName);

            if (user == null)
            {
                return new APIResponseDto<LoginResponseDto>
                {
                    IsSuccess = false,
                    StatusCode = 404,
                    Message = $"User with userName: {userName} does not exist.",
                };
            }

            var signIn = await _signInManager.TwoFactorSignInAsync(
                                                "Email",
                                                twoFToken,
                                                false,
                                                false
            );

            if (signIn.Succeeded)
            {
                if (user is not null)
                {
                    return await GetJwtTokenAsync(user);
                }
            }

            return new APIResponseDto<LoginResponseDto>
            {
                IsSuccess = false,
                StatusCode = 400,
                Message = $"Invalid twoFToken.",
                Response = new LoginResponseDto
                {

                }
            };
        }

        public async Task<APIResponseDto<LoginResponseDto>> RenewAccessTokenAsync(LoginResponseDto tokens)
        {
            var accessToken = tokens.AccessToken;

            var refreshToken = tokens.RefreshToken;

            var principal = GetClaimsPrincipal(accessToken.TokenContext!);

            var user = await _userManager.FindByNameAsync(principal.Identity!.Name);

            if (refreshToken!.TokenContext != user.RefreshToken && refreshToken.ExpiryTokenDate <= DateTime.Now)
            {
                return new APIResponseDto<LoginResponseDto>
                {
                    IsSuccess = false,
                    StatusCode = 400,
                    Message = $"Invalid refresh Token or expired. User must re-login.",
                    
                };
            }
            
            var response = await GetJwtTokenAsync(user);

            return response;
        }

        private ClaimsPrincipal GetClaimsPrincipal(string accessToken)
        {
            var tokenValidationParameter = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"])),
                ValidateLifetime = false                
            };

            var tokenHandler = new JwtSecurityTokenHandler();

            var principal = tokenHandler.ValidateToken(
                                            accessToken, 
                                            tokenValidationParameter, 
                                            out SecurityToken securityToken
            );

            return principal;
        }
    }
}
