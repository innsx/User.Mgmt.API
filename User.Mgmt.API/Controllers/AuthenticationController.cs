using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;
using User.Mgmt.API.Models;
using User.Mgmt.Service.Exentions;
using User.Mgmt.Service.Models;
using User.Mgmt.Service.Models.Authentication.Login;
using User.Mgmt.Service.Models.Authentication.SignUp;
using User.Mgmt.Service.Models.Authentication.UserResponse;
using User.Mgmt.Service.Services;
using User.Mgmt.Data.Models;

namespace User.Mgmt.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IEmailService _emailService;
        private readonly IUserMgmtService _userMgmtService;

        public AuthenticationController(UserManager<ApplicationUser> userManager,
                                        IEmailService emailService,
                                        IUserMgmtService userMgmtService)
        {
            _userManager = userManager;
            _emailService = emailService;
            _userMgmtService = userMgmtService;
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

                    var controller = "Authentication";

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

                    var isSendEmailSuccessful = _emailService.SendEmails(message);

                    if (isSendEmailSuccessful is true)
                    {
                        return StatusCode(
                            StatusCodes.Status200OK,
                            new ResponseDto
                            {
                                Status = "Success",
                                Message = $"Email sent to {registerUserDto.Email}. Open Link to verify your email account.",
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

                var isSendEmailSucceed = _emailService.SendEmails(message);

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
        public async Task<IActionResult> LoginWith2FToken(string twoFToken, string username)
        { 
            var validateLogin2FTokenResponse = 
                await _userMgmtService.ValidatesLoginUser2FTokenAsnyc(twoFToken, username);

            if (validateLogin2FTokenResponse.IsSuccess is true)
            {
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

                object messageContent = new { 
                    passwordResetToken, //NOTE: these parameters MUST match the 'passwordResetToken' 'email' parameters name in the GetPasswordResetToken action method
                    email = appUser.Email 
                };

                var forgotPasswordUrlContent = Url.Action(
                                                    callBackActionMethod,
                                                    controller,
                                                    messageContent,
                                                    Request.Scheme
                );

                IEnumerable<string> emailTos = new string[] { appUser.Email };

                var subject = "Forgot Passsword Confirmation Link:";

                var message =  new Message(emailTos, subject, forgotPasswordUrlContent!);

                bool isSendEmailSucceed = _emailService.SendEmails(message);

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
    }
}





//var user = await _userManager.FindByEmailAsync(passwordResetRequestDto.Email);

//if (user is not null)
//{
//    var passwordResetResponse = 
//        await _userManager.ResetPasswordAsync(user, passwordResetRequestDto.PasswordResetToken, passwordResetRequestDto.Password);

//    if (passwordResetResponse.Succeeded is false)
//    {
//        foreach (var error in passwordResetResponse.Errors)
//        {
//            ModelState.AddModelError(error.Code, error.Description);
//        }

//        return Ok(ModelState);
//    }

//    return StatusCode(
//        StatusCodes.Status200OK,
//        new ResponseDto
//        {
//            Status = "Success",
//            Message = $"Password reset and saved.",
//            IsSuccess = true
//        });
//}

//return StatusCode(
//    StatusCodes.Status404NotFound,
//    new ResponseDto
//    {
//        Status = "Error",
//        Message = $"User not found. Password reset failed.",
//        IsSuccess = false
//    });








//var isSendEmailSuccessful = 
//    _userMgmtService.EmailConfirmationLink(EmailRegisteredUserConfirm, registerUserDto, createdUserResponse);


//return StatusCode(
//    StatusCodes.Status200OK,
//    new ResponseDto
//    {
//        Status = "Success",
//        Message = $"Email sent to {registerUserDto.Email}. Open Link to verify your email account.",
//        IsSuccess = true
//    });






//if (validateLoginUserResponse.StatusCode == 400)
//{
//    return StatusCode(
//        StatusCodes.Status400BadRequest,
//        new ResponseDto
//        {
//            Status = "Error",
//            //Message = $"Renew Access Token and Refresh Token Failed.",
//            Message = validateLoginUserResponse.Message,
//            IsSuccess = false
//        });
//}

//if (validateLoginUserResponse.StatusCode == 404)
//{
//    return StatusCode(
//        StatusCodes.Status404NotFound,
//        new ResponseDto
//        {
//            Status = "Error",
//            Message = $"Refresh Token not found.",
//            IsSuccess = false
//        });
//}











//var appUser = await _userManager.FindByEmailAsync(email);

//if (appUser is not null)
//{
//    if (appUser.EmailConfirmed is false)
//    {
//        //confirm User’s Email and UPDATE AspNetUser table EmailConfirmed column to a ‘1’ for TRUE
//        var updateConfirmEmailFlag = await _userManager.ConfirmEmailAsync(appUser, token);

//        if (updateConfirmEmailFlag.Succeeded is true)
//        {
//            return StatusCode(
//                StatusCodes.Status200OK,
//                new ResponseDto
//                {
//                    Status = "Success",
//                    Message = $"Email: {email} verified and confirmed successfully.",
//                    IsSuccess = true
//                });
//        }
//    }

//    return StatusCode(
//        StatusCodes.Status400BadRequest,
//        new ResponseDto
//        {
//            Status = "Error",
//            Message = $"User's Email already confirmed.",
//            IsSuccess = false
//        });
//}

//return StatusCode(
//        StatusCodes.Status500InternalServerError,
//        new ResponseDto
//        {
//            Status = "Error",
//            Message = $"User's Email: {email} does not exist.",
//            IsSuccess = false
//        });