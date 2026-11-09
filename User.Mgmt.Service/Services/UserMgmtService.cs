using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Mail;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using User.Mgmt.API.Models;
using User.Mgmt.Data.Enums;
using User.Mgmt.Data.Models;
using User.Mgmt.Service.Models;
using User.Mgmt.Service.Models.Authentication.Login;
using User.Mgmt.Service.Models.Authentication.SignUp;
using User.Mgmt.Service.Models.Authentication.UserResponse;

namespace User.Mgmt.Service.Services
{
    public class UserMgmtService : IUserMgmtService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly JwtSettings _jWTSettingsSection;
        private readonly IEmailService _emailService;

        public UserMgmtService(UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager,
            SignInManager<ApplicationUser> signInManager,
            IOptions<JwtSettings> jwtSettingsSection,
            IEmailService emailService)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _signInManager = signInManager;
            _jWTSettingsSection = jwtSettingsSection.Value;
            _emailService = emailService;
         }

        public async Task<APIResponseDto<List<string>>> AssignsRoleToUserAsync(List<string> roles, ApplicationUser appUser)
        {
            var assignedRoles = new List<string>();

            var isRoleNullEmpty = string.IsNullOrEmpty(roles.ToString());

            if (roles.Count > 0 && isRoleNullEmpty is false)
            {
                foreach (var role in roles)
                {
                    if (await _roleManager.RoleExistsAsync(role) is true)
                    {
                        if (await _userManager.IsInRoleAsync(appUser, role) is false)
                        {
                            await _userManager.AddToRoleAsync(appUser, role);

                            assignedRoles.Add(role);
                        }
                        else
                        {
                            return new APIResponseDto<List<string>>
                            {
                                IsSuccess = false,
                                StatusCode = 204,
                                Message = "Role already assigned."
                            };
                        }
                    }
                    else
                    {
                        return new APIResponseDto<List<string>>
                        {
                            IsSuccess = false,
                            StatusCode = 204,
                            Message = "Role not exist in system."
                        };
                    }
                }

                return new APIResponseDto<List<string>>
                {
                    IsSuccess = true,
                    StatusCode = 200,
                    Message = "Role(s) assigned.",
                    Response = assignedRoles
                };
            }
            else
            {
                var defaultRole = Roles.Guest.ToString();

                if (await _roleManager.RoleExistsAsync(defaultRole) is true)
                {
                    if (await _userManager.IsInRoleAsync(appUser, defaultRole) is false)
                    {
                        await _userManager.AddToRoleAsync(appUser, defaultRole);

                        assignedRoles.Add(defaultRole);
                    }

                    return new APIResponseDto<List<string>>
                    {
                        IsSuccess = false,
                        StatusCode = 204,
                        Message = "Role already assigned."
                    };
                }

                return new APIResponseDto<List<string>>
                {
                    IsSuccess = true,
                    StatusCode = 200,
                    Message = $"A Default \'{Roles.Guest.ToString()}' Role has been assigned.",
                    Response = assignedRoles
                };
            }
        }

        public async Task<APIResponseDto<CreateUserReponseDto>> CreatesRegisterUserAsnyc(RegisterUserRequestDto registerUserResponseDto)
        {
            bool isEmailValid = IsValidEmailParser(registerUserResponseDto.Email);

            if (isEmailValid is true)
            {
                //check user exists in DB
                var userExist = await _userManager.FindByEmailAsync(registerUserResponseDto.Email);

                if (userExist is not null)
                {
                    return new APIResponseDto<CreateUserReponseDto>
                    {
                        IsSuccess = false,
                        StatusCode = 400,
                        Message = "User Email already taken."
                    };
                }

                // instantiate a new ApplicationUser
                ApplicationUser appUser = new ApplicationUser()
                {
                    Email = registerUserResponseDto.Email,
                    SecurityStamp = Guid.NewGuid().ToString(),
                    UserName = registerUserResponseDto.Username,
                };

                var createAppUser = await _userManager.CreateAsync(appUser, registerUserResponseDto.Password);

                if (createAppUser.Succeeded is true)
                {
                    var registrationToken = await _userManager.GenerateEmailConfirmationTokenAsync(appUser);

                    return new APIResponseDto<CreateUserReponseDto>
                    {
                        IsSuccess = true,
                        StatusCode = 200,
                        Message = "New application User created.",
                        Response = new CreateUserReponseDto()
                        {
                            Token = registrationToken,
                            User = appUser
                        }
                    };
                }

                return new APIResponseDto<CreateUserReponseDto>
                {
                    IsSuccess = false,
                    StatusCode = 400,
                    Message = $"Password must contain 1 uppercase, 1 lowercase, a digit, spcl char: -._+!@#$%^&*"
                };
            }

            return new APIResponseDto<CreateUserReponseDto>
            {
                IsSuccess = false,
                StatusCode = 400,
                Message = $"Email is invalid."
            };
        }

        private bool IsValidEmailParser(string email)
        {
            if (string.IsNullOrWhiteSpace(email))
                return false;

            try
            {
                // Throws FormatException if the structural layout is wrong
                var mailAddress = new MailAddress(email);
                return true;
            }
            catch (FormatException)
            {
                return false;
            }
        }

        public async Task<APIResponseDto<LoginTokensResponseDto>> GeneratesAccessNRefreshTokensAsync(ApplicationUser appUser)
        {
            List<Claim> authClaims = await CreatesClaimsNAddRolesAsnyc(appUser);

            if (authClaims.Any() is true)
            {
                var generatedAccessToken = GeneratesAccessToken(authClaims);

                if (generatedAccessToken is not null)
                {
                    //var refreshToken = _configuration["JWTSettingsSection:RefreshTokenValidity"];
                    var refreshToken = _jWTSettingsSection.RefreshTokenValidity.ToString();
                    _ = int.TryParse(refreshToken, out int refreshTokenValidity);

                    appUser.RefreshToken = GeneratesRefreshToken();

                    appUser.RefreshTokenExpiry = DateTime.UtcNow.AddDays(refreshTokenValidity);

                    await _userManager.UpdateAsync(appUser);

                    return new APIResponseDto<LoginTokensResponseDto>
                    {
                        IsSuccess = true,
                        StatusCode = 200,
                        Message = "Successfully generated Refresh Token.",
                        Response = new LoginTokensResponseDto()
                        {
                            AccessToken = new JwtTokenTypeResponseDto
                            {
                                TokenContext = new JwtSecurityTokenHandler().WriteToken(generatedAccessToken),
                                ExpiryTokenDate = generatedAccessToken.ValidTo
                            },
                            RefreshToken = new JwtTokenTypeResponseDto
                            {
                                TokenContext = appUser.RefreshToken,
                                ExpiryTokenDate = appUser.RefreshTokenExpiry
                            }
                        }
                    };
                }
            }

            return new APIResponseDto<LoginTokensResponseDto>
            {
                IsSuccess = false,
                StatusCode = 2004,
                Message = "Failed to generate Access Jwt Token.",
            };
        }

        private async Task<List<Claim>> CreatesClaimsNAddRolesAsnyc(ApplicationUser appUser)
        {
            var authClaims = new List<Claim>()
            {
                new Claim(ClaimTypes.NameIdentifier, appUser.Id),
                new Claim(ClaimTypes.Name, appUser.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var rolesFromDb = await _userManager.GetRolesAsync(appUser);

            if (rolesFromDb.Any() is true)
            {
                foreach (var role in rolesFromDb)
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

        private JwtSecurityToken GeneratesAccessToken(List<Claim> authClaims)
        {
            //var secretKey = Encoding.UTF8.GetBytes(_configuration["JWTSettingsSection:Secret"]);
            var secretKey = Encoding.UTF8.GetBytes(_jWTSettingsSection.Secret!);

            var authSigningKey = new SymmetricSecurityKey(secretKey);

            //var tokenValdInMinutes = _configuration["JWTSettingsSection:TokenValidationInMinutes"];
            var tokenValdInMinutes = _jWTSettingsSection.TokenValidationInMinutes.ToString();
            _ = int.TryParse(tokenValdInMinutes, out int tokenValidationInMinutes);

            var expirationTimeUtc = DateTime.UtcNow.AddMinutes(tokenValidationInMinutes);

            var localTimeZone = TimeZoneInfo.Local;

            var expirationTimeInLocalTimeZone = TimeZoneInfo.ConvertTimeFromUtc(expirationTimeUtc, localTimeZone);

            var credentials = new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256);

            var accessToken = new JwtSecurityToken(
                issuer: _jWTSettingsSection.ValidIssuer, //_configuration["JWTSettingsSection:ValidIssuer"],
                audience: _jWTSettingsSection.ValidAudience, //_configuration["JWTSettingsSection:ValidAudience"],
                expires: expirationTimeInLocalTimeZone,
                claims: authClaims,
                signingCredentials: credentials
            );

            return accessToken;
        }

        public async Task<APIResponseDto<LoginUser2FTokenResponseDto>> Generates2FTokenAsync(LoginRequestDto loginRequestDto)
        {
            //checking user exists in system
            var appUser = await _userManager.FindByNameAsync(loginRequestDto.Username);

            if (appUser is not null)
            {
                if (appUser.TwoFactorEnabled is false)
                {
                    appUser.TwoFactorEnabled = true;

                    await _userManager.UpdateAsync(appUser);

                    return await Generates2FToken(appUser, loginRequestDto);
                }
                else
                {
                    return await Generates2FToken(appUser, loginRequestDto);
                }
            }

            return new APIResponseDto<LoginUser2FTokenResponseDto>
            {
                StatusCode = 404,
                Message = $"User not found.",
                IsSuccess = false
            };
        }

        private async Task<APIResponseDto<LoginUser2FTokenResponseDto>> Generates2FToken(ApplicationUser appUser, LoginRequestDto loginRequestDto)
        {
            string generatedTwoFToken = string.Empty;

            var twoFProviders = await _userManager.GetValidTwoFactorProvidersAsync(appUser);

            if (twoFProviders.Contains("Email"))
            {
                //first sign-out current user
                await _signInManager.SignOutAsync();

                //re-sign-in User with loginRequestDto.Password
                await _signInManager.PasswordSignInAsync(
                                        appUser,
                                        loginRequestDto.Password,
                                        false,
                                        true
                );

                generatedTwoFToken = await _userManager.GenerateTwoFactorTokenAsync(appUser, "Email");

                if (generatedTwoFToken is not null)
                {
                    return new APIResponseDto<LoginUser2FTokenResponseDto>
                    {
                        StatusCode = 200,
                        Message = $"OTP is created.",
                        IsSuccess = true,
                        Response = new LoginUser2FTokenResponseDto()
                        {
                            User = appUser,
                            TwoFToken = generatedTwoFToken,
                            IsTwoFactorEnabled = appUser.TwoFactorEnabled
                        }
                    };
                }
            }

            return new APIResponseDto<LoginUser2FTokenResponseDto>
            {
                StatusCode = 400,
                Message = $"Failed to send email. Unable to generate Two Factor Token.",
                IsSuccess = false,
                Response = new LoginUser2FTokenResponseDto()
                {
                    User = appUser,
                    TwoFToken = string.Empty,
                    IsTwoFactorEnabled = false
                }
            };
        }

        private string GeneratesRefreshToken()
        {
            var randomNumber = new byte[64];
            var range = RandomNumberGenerator.Create();
            range.GetBytes(randomNumber);

            return Convert.ToBase64String(randomNumber);
        }

        public async Task<APIResponseDto<LoginUser2FTokenResponseDto>> AuthenticatesLoginUserAsync(LoginRequestDto loginRequestDto)
        {
            var appUser = await _userManager.FindByNameAsync(loginRequestDto.Username);

            if (appUser is null)
            {
                return new APIResponseDto<LoginUser2FTokenResponseDto>
                {
                    IsSuccess = false,
                    StatusCode = 404,
                    Message = $"User with userName: {loginRequestDto.Username} does not exist.",
                };
            }

            return new APIResponseDto<LoginUser2FTokenResponseDto>
            {
                IsSuccess = true,
                StatusCode = 200,
                Message = $"User with userName: {loginRequestDto.Username} exist.",
            };
        }

        public async Task<APIResponseDto<LoginTokensResponseDto>> AuthenticateLoginUser2FTokenAsnyc(string twoFToken, string userName)
        {
            var appUser = await _userManager.FindByNameAsync(userName);

            if (appUser is null)
            {
                return new APIResponseDto<LoginTokensResponseDto>
                {
                    IsSuccess = false,
                    StatusCode = 404,
                    Message = $"User with userName: {userName} does not exist.",
                };
            }
            var providers = await _userManager.GetValidTwoFactorProvidersAsync(appUser);

            if (providers.Contains("Email"))
            {
                var signIn = await _signInManager.TwoFactorSignInAsync(
                                    "Email",
                                    twoFToken,
                                    false,
                                    false
);

                if (signIn.Succeeded is true)
                {
                    appUser.TwoFactorEnabled = true;
                    return await GeneratesAccessNRefreshTokensAsync(appUser);
                }
                else
                {
                    return new APIResponseDto<LoginTokensResponseDto>
                    {
                        IsSuccess = false,
                        StatusCode = 404,
                        Message = $"Failed to login with Two Factor Token. Token may have been expired, please Login again.",
                    };
                }
            }

            return new APIResponseDto<LoginTokensResponseDto>
            {
                IsSuccess = false,
                StatusCode = 400,
                Message = $"Invalid twoFToken.",
                Response = new LoginTokensResponseDto
                {

                }
            };
        }

        public async Task<APIResponseDto<LoginUser2FTokenResponseDto>> CreatesEmailConfirmation2FTokenAsync(APIResponseDto<LoginUser2FTokenResponseDto> generates2FTokenResponse)
        {
            var appUser = generates2FTokenResponse.Response!.User;
            var twoFToken = generates2FTokenResponse.Response.TwoFToken;

            var message = new Message(
                            new string[] { appUser.Email! },
                            "OTP 2 factor token email confirmation link.",
                            twoFToken);   //NOTE: this parameteer MUST match the 'twoFToken' parameter name in the LoginWith2FToken action method

            var isSendEmailSucceed = await _emailService.ComposeNSendEmailsAsync(message);

            if (isSendEmailSucceed is true)
            {
                return new APIResponseDto<LoginUser2FTokenResponseDto>
                {
                    IsSuccess = true,
                    StatusCode = 200,
                    Message = $"Email was sent to  {generates2FTokenResponse.Response!.User.Email} account",
                };
            }

            return new APIResponseDto<LoginUser2FTokenResponseDto>                 
                {
                    StatusCode = 404,
                    Message = $"Email was not sent to: {appUser.Email} to perform an OTP (2 factor Authentication).",
                    IsSuccess = false
                };
        }
        
        public async Task<APIResponseDto<LoginTokensResponseDto>> RenewAccessNRefreshTokensAsync(LoginTokensResponseDto tokens)
        {
            var oldAccessToken = tokens.AccessToken;

            var oldRefreshToken = tokens.RefreshToken;

            var claimPrincipal = GetClaimsPrincipal(oldAccessToken.TokenContext!);

            if (claimPrincipal is null)
            {
                return new APIResponseDto<LoginTokensResponseDto>
                {
                    IsSuccess = false,
                    StatusCode = 400,
                    Message = $"Failed to retrieve Claim Principal based of User's Old Access Token."
                };
            }

            ApplicationUser appUser = await _userManager.FindByNameAsync(claimPrincipal.Identity!.Name);

            if (oldRefreshToken!.TokenContext == appUser.RefreshToken)  //AppUser's RefreshToken matched                            
            {
                if (oldRefreshToken.ExpiryTokenDate >= DateTime.Now) //and Old refresh Token has not expired
                {
                    return new APIResponseDto<LoginTokensResponseDto>
                    {
                        IsSuccess = false,
                        StatusCode = 400,
                        Message = $"Old Refresh Token has not expired. User must re-login.",
                    };
                }
                var generatedAccessNRefreshTokensResponse = await GeneratesAccessNRefreshTokensAsync(appUser);

                if (generatedAccessNRefreshTokensResponse.IsSuccess is true)
                {
                    return generatedAccessNRefreshTokensResponse;
                }

                return new APIResponseDto<LoginTokensResponseDto>
                {
                    IsSuccess = false,
                    StatusCode = 400,
                    Message = $"Renew Access and Refresh Tokens Failed.",
                };
            }

            return new APIResponseDto<LoginTokensResponseDto>
            {
                IsSuccess = false,
                StatusCode = 404,
                Message = $"Old Refresh Token does not found in System.",
            };
        }

        private ClaimsPrincipal? GetClaimsPrincipal(string oldAccessToken)
        {
            var secrets = Encoding.UTF8.GetBytes(_jWTSettingsSection.Secret!);

            var tokenValidationParameter = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(secrets),
                ValidateLifetime = false
            };

            var tokenHandler = new JwtSecurityTokenHandler();

            var claimsPrincipal = new ClaimsPrincipal();

            try
            {
                claimsPrincipal = tokenHandler.ValidateToken(
                                        oldAccessToken,
                                        tokenValidationParameter,
                                        out SecurityToken securityToken);
            }
            catch (Exception ex)
            {
                throw new NullReferenceException(ex.Message.ToString());
            }

            return claimsPrincipal;
        }

        public async Task<APIResponseDto<LoginTokensResponseDto>> ResetPasswordAsync(PasswordResetRequestDto passwordResetRequestDto)
        {
            var user = await _userManager.FindByEmailAsync(passwordResetRequestDto.Email);

            if (user is not null)
            {
                var resetPasswordResult =
                    await _userManager.ResetPasswordAsync(user, passwordResetRequestDto.PasswordResetToken, passwordResetRequestDto.Password);

                if (resetPasswordResult.Succeeded is false)
                {
                    return
                        new APIResponseDto<LoginTokensResponseDto>
                        {
                            StatusCode = 400,
                            Message = $"Password reset failed.",
                            IsSuccess = false
                        };
                }
            }

            return
                new APIResponseDto<LoginTokensResponseDto>
                {
                    StatusCode = 200,
                    Message = $"Password reset successfully.",
                    IsSuccess = true
                };
        }

        public async Task<APIResponseDto<LoginTokensResponseDto>> ValidatesRegistrationTokenAsync(string token, string email)
        {
            var appUser = await _userManager.FindByEmailAsync(email);

            if (appUser is not null)
            {
                if (appUser.EmailConfirmed is false)
                {
                    //confirm User’s Email and UPDATE AspNetUser table EmailConfirmed column to a ‘1’ for TRUE
                    var updateConfirmEmailFlag = await _userManager.ConfirmEmailAsync(appUser, token);

                    if (updateConfirmEmailFlag.Succeeded is true)
                    {
                        return
                            new APIResponseDto<LoginTokensResponseDto>
                            {
                                StatusCode = 200,
                                Message = $"Email: {email} verified and confirmed successfully.",
                                IsSuccess = true
                            };
                    }
                }

                return new APIResponseDto<LoginTokensResponseDto>
                {
                    StatusCode = 201,
                    Message = $"Email already confirmed.",
                    IsSuccess = false
                };
            }

            return new APIResponseDto<LoginTokensResponseDto>
            {
                StatusCode = 404,
                Message = $"User's does not exist.",
                IsSuccess = false
            };
        }

        public async Task<ResponseDto> GetPasswordResetTokenAsync(PasswordResetRequestDto passwordResetRequestDto)
        {
            var user = await _userManager.FindByEmailAsync(passwordResetRequestDto.Email);

            if (user is not null)
            {
                var passwordResetResponse =
                    await _userManager.ResetPasswordAsync(user, passwordResetRequestDto.PasswordResetToken, passwordResetRequestDto.Password);

                if (passwordResetResponse.Succeeded is false)
                {
                    return new ResponseDto
                    {
                        Status = "Error",
                        Message = $"Password reset failed: {passwordResetResponse.Errors.FirstOrDefault()?.Description}.",
                        IsSuccess = false
                    };
                }

                return
                    new ResponseDto
                    {
                        Status = "Success",
                        Message = $"Password reset and saved.",
                        IsSuccess = true
                    };
            }


            return
                new ResponseDto
                {
                    Status = "Failed",
                    Message = $"User not found.",
                    IsSuccess = false
                };
        }

        public async Task<ApplicationUser> GetUserAsync(LoginRequestDto loginRequestDto)
        {
            var appUser = await _userManager.FindByNameAsync(loginRequestDto.Username);
            if (appUser is not null)
            {
                return appUser;
            }
            return new ApplicationUser();
        }

        public async Task<ResponseDto> CheckPasswordSigninAsync(LoginRequestDto loginRequestDto, ApplicationUser user)
        {
            var passwordCheck = await _signInManager.CheckPasswordSignInAsync(user, loginRequestDto.Password, false);
            if (passwordCheck.Succeeded is true)
            {
                return new ResponseDto
                {
                    Status = "Success",
                    Message = $"Password matched.",
                    IsSuccess = true
                };
            }
            return new ResponseDto
            {
                Status = "Failed",
                Message = $"Password does not match.",
                IsSuccess = false
            };
        }

        public Message GeneratesEmailMessageWith2FToken(APIResponseDto<LoginUser2FTokenResponseDto> generates2FTokenResponse)
        {
            var message = new Message(
                new string[]
                {
                    generates2FTokenResponse.Response!.User!.Email!
                },
                "Two Factor Token",
                $"Your Two Factor Token is: {generates2FTokenResponse.Response.TwoFToken}");
            return message;
        }

        public async Task UserLogoutAsync()
        {
            await _signInManager.SignOutAsync();
        }
    }
}




//public APIResponseDto<LoginTokensResponseDto> EmailConfirmationLink(Func<string, string, Task<IActionResult>> EmailRegisteredUserConfirm, RegisterUserRequestDto registerUserDto, APIResponseDto<CreateUserReponseDto> createdUserResponse)
//{
//    var callBackActionMethod = nameof(EmailRegisteredUserConfirm);

//    var controller = "Authentication";

//    object messageContent = new
//    {
//        createdUserResponse.Response!.Token,
//        registerUserDto.Email
//    };

//    var controllerBaseInstance = new AuthenticationController();

//    var registrationEmailConfirmationLink = controllerBaseInstance.Url.Action(
//                       callBackActionMethod, //CALLBACK Endpoint in AuthenticationController.cs
//                       controller,    //"AuthenticationController" 
//                       messageContent,
//                       controllerBaseInstance.Request.Scheme); //MUST specified or else it will not create a URL link

//    var message = new Message(
//                        new string[]
//                        {
//                            registerUserDto.Email!
//                        },
//                        "Registration confirmation email link.",
//                        registrationEmailConfirmationLink!);

//    var isSendEmailSuccessful = _emailService.SendEmails(message);

//    if (isSendEmailSuccessful is true)
//    {
//        return new APIResponseDto<LoginTokensResponseDto>
//        {
//            StatusCode = 200,
//            Message = $"Email sent to {registerUserDto.Email}. Open Link to verify your email account.",
//            IsSuccess = true
//        };
//    }

//    return new APIResponseDto<LoginTokensResponseDto>
//    {
//        StatusCode = 404,
//        Message = $"Failed to send email to {registerUserDto.Email}.",
//        IsSuccess = false
//    };
//}






//public Task<ResetPasswordRequestDto> GetResetPasswordTokenAsync(string resetPasswordToken, string email)
//{
//    var result = new ResetPasswordRequestDto
//    {
//        ResetPasswodToken = resetPasswordToken,
//        Email = email
//    };

//    return result;
//}


//public Message CreateConfirmationEmailLink(APIResponseDto<CreateUserReponseDto> createdUser, RegisterUserRequestDto registerUserRequestDto, ControllerBase baseUrl)
//{
//    string ConfirmEmail = string.Empty;
//    var callBackActionMethod = nameof(ConfirmEmail);
//    var controller = "Authentication";
//    object emailContent = new
//    {
//        createdUser.Response!.Token,
//        registerUserRequestDto.Email
//    };

//    var confirmationLink = baseUrl.Url.Action(
//                            callBackActionMethod, //CALLBACK Endpoint in AuthenticationController.cs
//                            controller,    //"AuthenticationController" 
//                            emailContent,
//                            baseUrl.Request.Scheme); //MUST specified or else it will not create a URL link

//    var message = new Message(
//                        new string[]
//                        {
//                            registerUserRequestDto.Email!
//                        },
//                        "Registration Confirmation email link.",
//                        confirmationLink!);

//    return message;
//}