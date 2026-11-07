using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using User.Mgmt.API.Models;
using User.Mgmt.Data.Models;
using User.Mgmt.Service.Exentions;
using User.Mgmt.Service.Models;
using User.Mgmt.Service.Models.Authentication.Login;
using User.Mgmt.Service.Models.Authentication.SignUp;
using User.Mgmt.Service.Models.Authentication.UserResponse;
using User.Mgmt.Service.Services;

namespace User.Mgmt.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IEmailService _emailService;
        private readonly IUserMgmtService _userMgmtService;
        private readonly ITokenBlacklistService _tokenBlacklistService;

        public AuthenticationController(UserManager<ApplicationUser> userManager,
                                        IEmailService emailService,
                                        IUserMgmtService userMgmtService,
                                        ITokenBlacklistService tokenBlacklistService)
        {
            _userManager = userManager;
            _emailService = emailService;
            _userMgmtService = userMgmtService;
            _tokenBlacklistService = tokenBlacklistService;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterUserRequestDto registerUserDto)
        {
            var createUserResponse = await _userMgmtService.CreatesRegisterUserAsnyc(registerUserDto);

            if (createUserResponse.IsSuccess is true)
            {
                var assignRoleToUser =
                    await _userMgmtService.AssignsRoleToUserAsync(registerUserDto.Roles!, createUserResponse.Response!.User!);

                if (assignRoleToUser.IsSuccess is true)
                {
                    var callBackActionMethod = nameof(RegistrationEmailConfirmation);

                    var controller = this.GetType().Name.Replace("Controller", string.Empty);

                    object messageContent = new
                    {
                        createUserResponse.Response.Token,  //NOTE: Token MUST match the 'token' parameter name in the RegistrationEmailConfirmation action method
                        registerUserDto.Email
                    };

                    var registrationEmailConfirmationLink = Url.Action(
                                       callBackActionMethod, //CALLBACK Endpoint in AuthenticationController.cs
                                       controller,    //"AuthenticationController" 
                                       messageContent,
                                       Request.Scheme); //MUST specified or else it will not create a URL link

                    var message = new Message(
                                        new string[]
                                        {
                                            registerUserDto.Email!
                                        },
                                        "Registration confirmation email link.",
                                        registrationEmailConfirmationLink!);

                    var isSendEmailSuccessful = _emailService.ComposeNSendEmails(message);

                    if (isSendEmailSuccessful is true)
                    {
                        return StatusCode(
                            StatusCodes.Status200OK,
                            new ResponseDto
                            {
                                Status = "Success",
                                Message = $"Email sent to {registerUserDto.Email}. Clicks Link to verify your email account.",
                                IsSuccess = true
                            });
                    }

                }
            }

            return StatusCode(
                    StatusCodes.Status500InternalServerError,
                    new ResponseDto
                    {
                        Status = "Error",
                        Message = createUserResponse.Message,
                        IsSuccess = createUserResponse.IsSuccess
                    });
        }

        [HttpGet("confirm-email")]
        public async Task<IActionResult> RegistrationEmailConfirmation(string token, string email)
        {
            //NOTE: input token & email parameters are coming from
            //the query string of the Registration Email Confirmaton URL link sent to the user's email.
            //so 'token' and 'email' names MUST match the query string parameter names
            //in the URL link sent to the user's email.

            //NOTE: we are not using _userManager.ConfirmEmailAsync()
            //because it will throw an error if the token is invalid or expired.
            //Instead, we are using our own service to validate the token and email.
            var validatesRegistrationTokenResponse =
                await _userMgmtService.ValidatesRegistrationTokenAsync(token, email);

            if (validatesRegistrationTokenResponse.IsSuccess is true)
            {
                return StatusCode(
                    StatusCodes.Status200OK,
                    new ResponseDto
                    {
                        Status = "Success",
                        Message = validatesRegistrationTokenResponse.Message,
                        IsSuccess = validatesRegistrationTokenResponse.IsSuccess
                    });
            }

            return StatusCode(
                 StatusCodes.Status500InternalServerError,
                 new ResponseDto
                 {
                     Status = "Error",
                     Message = validatesRegistrationTokenResponse.Message,
                     IsSuccess = validatesRegistrationTokenResponse.IsSuccess
                 });

        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequestDto loginRequestDto)
        {
            var generates2FTokenResponse = await _userMgmtService.Generates2FTokenAsync(loginRequestDto);

            if (generates2FTokenResponse.Response is not null)
            {
                var appUser = generates2FTokenResponse.Response.User;
                var twoFToken = generates2FTokenResponse.Response.TwoFToken;

                var message = new Message(
                                new string[] { appUser.Email! },
                                "OTP 2 factor token email confirmation link.",
                                twoFToken);   //NOTE: this parameteer MUST match the 'twoFToken' parameter name in the LoginWith2FToken action method

                var isSendEmailSucceed = _emailService.ComposeNSendEmails(message);

                if (isSendEmailSucceed is true)
                {
                    return StatusCode(
                        StatusCodes.Status200OK,
                        new ResponseDto
                        {
                            Status = "Success",
                            Message = $"An Email has been sent to: {appUser.Email} to perform an OTP (2 factor Authentication).",
                            IsSuccess = generates2FTokenResponse.IsSuccess
                        });
                }

                return StatusCode(
                    StatusCodes.Status400BadRequest,
                    new ResponseDto
                    {
                        Status = "Error",
                        Message = $"Email was not sent to: {appUser.Email} to perform an OTP (2 factor Authentication).",
                        IsSuccess = false
                    });
            }

            //if user not exist, we're returning an Unauthorized result
            return Unauthorized();
        }


        [HttpPost("login-withTwoFToken")]
        public async Task<IActionResult> LoginWith2FToken(string twoFToken, string userName)
        {
            var validateLogin2FTokenResponse =
                await _userMgmtService.ValidatesLoginUser2FTokenAsnyc(twoFToken, userName);

            if (validateLogin2FTokenResponse.IsSuccess is true)
            {
                var token = validateLogin2FTokenResponse.Response!.AccessToken;

                var cookieOptions = new CookieOptions
                {
                    Path = "/",
                    HttpOnly = true,        // Prevents client-side JS from reading the cookie
                    Secure = true,          // Required for HTTPS
                    IsEssential = true,      // Required for GDPR compliance
                    SameSite = SameSiteMode.Strict, // Or Lax depending on your frontend setup
                    Expires = DateTime.UtcNow.AddHours(2) //token expiration
                };

                HttpContext.Response.Cookies.Append("HttpOnlyCookieToken", token.ToString()!, cookieOptions);

                return Ok(validateLogin2FTokenResponse);
            }

            return StatusCode(
                StatusCodes.Status404NotFound,
                new ResponseDto
                {
                    Status = "Error",
                    //Message = $"Invalid OTP (2 factor Token).",
                    Message = validateLogin2FTokenResponse.Message,
                    IsSuccess = validateLogin2FTokenResponse.IsSuccess
                });
        }


        [HttpPost("forgot-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ForgotPassword([Required] string email)
        {
            var appUser = await _userManager.FindByEmailAsync(email);

            if (appUser is not null)
            {
                var passwordResetToken = await _userManager.GeneratePasswordResetTokenAsync(appUser);

                string callBackActionMethod = nameof(GetPasswordResetToken);

                string controller = "Authentication";

                object messageContent = new
                {
                    passwordResetToken, //NOTE: these parameters MUST match the 'passwordResetToken' &
                    email = appUser.Email  //'email' parameters name in the GetPasswordResetToken action method
                };

                var forgotPasswordUrlContent = Url.Action(
                                                    callBackActionMethod,
                                                    controller,
                                                    messageContent,
                                                    Request.Scheme
                );

                IEnumerable<string> emailTos = new string[] { appUser.Email };

                var subject = "Forgot Passsword Confirmation Link:";

                var message = new Message(emailTos, subject, forgotPasswordUrlContent!);

                bool isSendEmailSucceed = _emailService.ComposeNSendEmails(message);

                if (isSendEmailSucceed is true)
                {
                    return StatusCode(
                        StatusCodes.Status200OK,
                    new ResponseDto
                    {
                        Status = "Success",
                        Message = $"Password reset request link is sent to: {email}.",
                        IsSuccess = true
                    });
                }
            }

            return StatusCode(
                StatusCodes.Status404NotFound,
                new ResponseDto
                {
                    Status = "Error",
                    Message = $"User's {email} not found in system.",
                    IsSuccess = false
                });
        }


        [HttpGet("get-password-reset-token")]
        public IActionResult GetPasswordResetToken(string passwordResetToken, string email)
        {
            var passwordResetResponse = new PasswordResetResponseDto
            {
                PasswordResetToken = passwordResetToken,
                Email = email
            };

            return Ok(new { passwordResetResponse });
        }


        [HttpPost]
        [Route("password-reset")]
        [AllowAnonymous]
        public async Task<IActionResult> PasswordReset(PasswordResetRequestDto passwordResetRequestDto)
        {
            var passwordResetResponse =
                await _userMgmtService.GetPasswordResetTokenAsync(passwordResetRequestDto);

            if (passwordResetResponse.IsSuccess is true)
            {
                return StatusCode(
                    StatusCodes.Status200OK,
                    new ResponseDto
                    {
                        Status = "Success",
                        Message = $"Password reset and saved.",
                        IsSuccess = true
                    });

            }
            return StatusCode(
                StatusCodes.Status404NotFound,
                new ResponseDto
                {
                    Status = "Error",
                    Message = $"User not found. Password reset failed.",
                    IsSuccess = false
                });
        }


        [HttpPost]
        [Route("refresh-tokens")]
        public async Task<IActionResult> RefreshTokens(LoginTokensResponseDto tokens)
        {
            var renewAccessNRefreshTokensResponse =
                await _userMgmtService.RenewAccessNRefreshTokensAsync(tokens);

            if (renewAccessNRefreshTokensResponse.IsSuccess is true
                && renewAccessNRefreshTokensResponse is not null)
            {
                return Ok(renewAccessNRefreshTokensResponse);
            }

            return StatusCode(
                StatusCodes.Status400BadRequest,
                new ResponseDto
                {
                    Status = "Error",
                    Message = renewAccessNRefreshTokensResponse!.Message,
                    IsSuccess = false
                });
        }


        [HttpPost("logout")]
        public async Task<IActionResult> Logout()
        {
            // 1. Extract JTI
            //var jti = User.FindFirst(JwtRegisteredClaimNames.Jti)?.Value;
            var jti = string.Empty;
            var jwtToken = new JwtSecurityToken();

            //HttpContext.Request.Cookies.TryGetValue("HttpOnlyCookieToken", out var token);

            string? rawToken = await HttpContext.GetTokenAsync("access_token");

            if (rawToken != null) {
                // 1. Extract JTI from the token
                var handler = new JwtSecurityTokenHandler();
                jwtToken = handler.ReadJwtToken(rawToken);
                jti = jwtToken.Id; // JTI claim is usually stored in the 'jti' property of the JWT
            }

            // 2. Extract expiration claim to calculate exact remaining TTL
            var expClaim = User.FindFirst(JwtRegisteredClaimNames.Exp)?.Value;

            if (string.IsNullOrEmpty(jti) || string.IsNullOrEmpty(expClaim))
            {
                return BadRequest("Invalid token claims.");
            }

            // 3. Calculate remaining lifetime
            var expirationTimeUnix = long.Parse(expClaim);
            var expirationDateTime = DateTimeOffset.FromUnixTimeSeconds(expirationTimeUnix).UtcDateTime;
            var remainingTime = (expirationDateTime - DateTime.UtcNow);

            // 4. Place token in Redis Blacklist if it's still alive
            if (remainingTime > TimeSpan.Zero)
            {
                await _tokenBlacklistService.BlacklistTokenAsync(jwtToken!);
            }

            var cookieOptions = new CookieOptions
            {
                Path = "/",
                Secure = true,
                //HttpOnly = true,
                SameSite = SameSiteMode.Strict // match original SameSite
            };

            // 5. Delete the HTTPOnly cookie Token (ensure options match path/domain if configured)
            Response.Cookies.Delete("HttpOnlyCookieToken", cookieOptions);

            // 6. Call the user management service to handle any additional logout logic
            await _userMgmtService.UserLogoutAsync();

            return StatusCode(
                StatusCodes.Status200OK,
                new ResponseDto
                {
                    Status = "Success",
                    Message = $"User logged out successfully.",
                    IsSuccess = true
                });
        }
    }
}








//    [HttpPost("logout")]
//    public async Task<IActionResult> Logout()
//    {
//        var authHeader = Request.Headers["Authorization"].ToString();

//        if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
//        {
//            return BadRequest("Invalid token header.");
//        }

//        var token = authHeader.Substring("Bearer ".Length).Trim();

//        // Revoke the token immediately by saving it to Redis blacklist
//        await _tokenBlacklistService.BlacklistTokenAsync(token);

//        // delete HTTPOnly cookie Token (ensure options match path/domain if configured)
//        Response.Cookies.Delete("SetTokenCookie");

//        return StatusCode(
//            StatusCodes.Status200OK,
//            new ResponseDto
//            {
//                Status = "Success",
//                Message = $"User logged out successfully.",
//                IsSuccess = true
//            });
//    }
//} 