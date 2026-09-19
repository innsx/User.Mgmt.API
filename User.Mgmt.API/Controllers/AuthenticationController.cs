using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;
using User.Mgmt.API.Models;
using User.Mgmt.Service.Models;
using User.Mgmt.Service.Models.Authentication.Login;
using User.Mgmt.Service.Models.Authentication.SignUp;
using User.Mgmt.Service.Models.Authentication.UserResponse;
using User.Mgmt.Service.Services;
using UserMgmt.Data.Models;

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

        [HttpPost("register-user")]
        public async Task<IActionResult> Register([FromBody] RegisterUserRequestDto registerUserDto)
        {
            var accessToken = await _userMgmtService.CreateUserWithTokenAsnyc(registerUserDto);

            if (accessToken.IsSuccess is true)
            {
                var isRoleAssigned = await _userMgmtService.AssignRoleToUserAsync(registerUserDto.Roles!, accessToken.Response!.User!);

                if (isRoleAssigned.IsSuccess is true)
                {
                    var actionMethod = nameof(ConfirmEmail);
                    var controller = "Authentication";
                    object objectContent = new { accessToken.Response.Token, registerUserDto.Email };

                    var confirmationLink = Url.Action(
                                            actionMethod, //CALLBACK Endpoint in AuthenticationController.cs
                                            controller,    //"AuthenticationController" 
                                            objectContent, 
                                            Request.Scheme); //MUST specified or else it will not create a URL link

                    var message = new Message(new string[] 
                                        { registerUserDto.Email! },
                                        "Confirmation email link",
                                        confirmationLink!);

                    var isSendEmailSuccessfull = _emailService.SendEmails(message);

                    if (isSendEmailSuccessfull is true)
                    {
                        return StatusCode(
                            StatusCodes.Status200OK,
                            new ResponseDto
                            {
                                Status = "Success",
                                Message = $"Email sent to {registerUserDto.Email}. Open Link to verify.",
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
                        Message = accessToken.Message,
                        IsSuccess = accessToken.IsSuccess
                    });

        }

        [HttpGet("confirm-email")]
        public async Task<IActionResult> ConfirmEmail(string token, string email)
        {
            var user = await _userManager.FindByEmailAsync(email);

            if (user is not null)
            {
                //this line confirm User’s Email and UPDATE AspNetUser table EmailConfirmed column to a ‘1’ for TRUE
                //and the User is assigned  with the Registered Role in AspNetUserRoles table
                var confirmEmail = await _userManager.ConfirmEmailAsync(user, token);

                if (confirmEmail.Succeeded is true)
                {
                    return StatusCode(
                        StatusCodes.Status200OK,
                        new ResponseDto
                        {
                            Status = "Success",
                            Message = $"Email: {email} verified successfully.",
                            IsSuccess = true
                        });
                }
            }

            return StatusCode(
                    StatusCodes.Status500InternalServerError,
                    new ResponseDto
                    {
                        Status = "Error",
                        Message = $"User's Email: {email} does not exist.",
                        IsSuccess = false
                    });
        }

        [HttpPost("login-user")]
        public async Task<IActionResult> Login([FromBody] LoginRequestDto loginRequestDto)
        {
            var otp2FTokenResponse = await _userMgmtService.Generate2FTokenAsync(loginRequestDto);

            if (otp2FTokenResponse.Response is not null)
            {
                var user = otp2FTokenResponse.Response.User;

                if (user.TwoFactorEnabled is true)
                {
                    var twoFToken = otp2FTokenResponse.Response.TwoFToken;

                    var message = new Message(
                        new string[] { user.Email! },
                        "OTP Email Confirmation",
                        twoFToken);

                    var isSendEmailSucced = _emailService.SendEmails(message);

                    if (isSendEmailSucced is true)
                    {
                        return StatusCode(
                            StatusCodes.Status200OK,
                            new ResponseDto
                            {
                                Status = "Success",
                                Message = $"An Email has been sent to: {user.Email} to perform an OTP (2 factor Authentication).",
                                IsSuccess = otp2FTokenResponse.IsSuccess
                            });
                    }

                    return StatusCode(
                        StatusCodes.Status400BadRequest,
                        new ResponseDto
                        {
                            Status = "Error",
                            Message = $"Email was not sent to: {user.Email} to perform an OTP (2 factor Authentication).",
                            IsSuccess = false
                        });
                }
                else if (user.TwoFactorEnabled is false)
                {
                    //enable TwoFactorEnabled to true

                    //
                    //checking user's password
                    var isPasswordExist = await _userManager.CheckPasswordAsync(user, loginRequestDto.Password);

                    if (user is not null && isPasswordExist is true)
                    {
                        var accessJwtToken = await _userMgmtService.GenerateAccessJwtTokenAsync(user);

                        return Ok(accessJwtToken);
                    }
                }
            }

            //if user not exist, we're returning an Unauthorized result
            return Unauthorized();
        }

        [HttpPost("login-withTwoFToken")]
        public async Task<IActionResult> LoginWith2FToken(string twoFToken, string username)
        { 
            var loginUserResponse = await _userMgmtService.LoginUserWith2FTokenAsnyc(twoFToken, username);

            if (loginUserResponse.IsSuccess is true)
            {
                return Ok(loginUserResponse);
            }

            return StatusCode(
                StatusCodes.Status404NotFound,
                new ResponseDto
                {
                    Status = "Error",
                    Message = $"An invalid OTP (2 factor Token).",
                    IsSuccess = false
                });
        }


        [HttpPost("forgot-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ForgotPassword([Required] string email)
        {
            var user = await _userManager.FindByEmailAsync(email);

            if (user is not null)
            {
                var resetPasswordToken = await _userManager.GeneratePasswordResetTokenAsync(user);

                string actionMethod = nameof(GetResetPasswordToken);
                string controller = "Authentication";
                object objectContent = new { resetPasswordToken, email = user.Email };

                var forgotPasswordLink = Url.Action(
                    actionMethod,
                    controller,
                    objectContent,
                    Request.Scheme
                );

                IEnumerable<string> emailTos = new string[] { user.Email };

                var subject = "Forgot Passsword Confirmation Link:";

                var message = new Message(emailTos, subject, forgotPasswordLink!);

                var isEmailSent =_emailService.SendEmails(message);

                if (isEmailSent is true)
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

                return StatusCode(
                    StatusCodes.Status200OK,
                    new ResponseDto
                    {
                        Status = "Error",
                        Message = $"Failed to send an email to: {email}.",
                        IsSuccess = false
                    });
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


        [HttpGet("get-reset-password-token")]
        public async Task<IActionResult> GetResetPasswordToken(string resetPasswordToken, string email)
        {
            var resetPasswordModel = new ResetPasswordRequestDto 
            { 
                ResetPasswodToken = resetPasswordToken, 
                Email = email 
            };

            return Ok(new { resetPasswordModel });
        }


        [HttpPost]
        [Route("reset-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword(ResetPasswordRequestDto resetPasswordRequestDto)
        {
            var user = await _userManager.FindByEmailAsync(resetPasswordRequestDto.Email);

            if (user is not null)
            {
                var resetPasswordResult = await _userManager.ResetPasswordAsync(user, resetPasswordRequestDto.ResetPasswodToken, resetPasswordRequestDto.Password);

                if (resetPasswordResult.Succeeded is false)
                {
                    foreach (var error in resetPasswordResult.Errors)
                    {
                        ModelState.AddModelError(error.Code, error.Description);
                    }

                    return Ok(ModelState);
                }

                return StatusCode(
                    StatusCodes.Status200OK,
                    new ResponseDto
                    {
                        Status = "Success",
                        Message = $"Password is reset/changed.",
                        IsSuccess = true
                    });
            }

            return StatusCode(
                StatusCodes.Status404NotFound,
                new ResponseDto
                {
                    Status = "Error",
                    Message = $"User with Email not found. Password reset failed.",
                    IsSuccess = false
                });
        }


        [HttpPost]
        [Route("refresh-token")]
        public async Task<IActionResult> RefreshToken(LoginTokensResponseDto tokens)
        {
            var renewAccessJwtTokenResponse = await _userMgmtService.RenewAccessJwtTokenAsync(tokens);

            if (renewAccessJwtTokenResponse.IsSuccess is true)
            {
                return Ok(renewAccessJwtTokenResponse);
            }

            return StatusCode(
                StatusCodes.Status404NotFound,
                new ResponseDto
                {
                    Status = "Error",
                    Message = $"Token not found.",
                    IsSuccess = false
                });
        }
    }

}
