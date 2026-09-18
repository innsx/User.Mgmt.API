using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;
using User.Mgmt.API.Models;
using User.Mgmt.Service.Models;
using User.Mgmt.Service.Models.Authentication.Login;
using User.Mgmt.Service.Models.Authentication.SignUp;
using User.Mgmt.Service.Services;
using UserMgmt.Data.Models;

namespace User.Mgmt.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<ApplicationUserDto> _userManager;
        private readonly IEmailService _emailService;
        private readonly IUserMgmtService _userMgmtService;

        public AuthenticationController(UserManager<ApplicationUserDto> userManager,
                                        IEmailService emailService,
                                        IUserMgmtService userMgmtService)
        {
            _userManager = userManager;
            _emailService = emailService;
            _userMgmtService = userMgmtService;
        }

        [HttpPost("register-user")]
        public async Task<IActionResult> Register([FromBody] RegisterUserDto registerUserDto)
        {
            var accessToken = await _userMgmtService.CreateUserWithTokenAsnyc(registerUserDto);

            if (accessToken.IsSuccess is true)
            {
                var isRoleAssigned = await _userMgmtService.AssignRoleToUserAsync(registerUserDto.Roles!, accessToken.Response!.User!);

                if (isRoleAssigned.IsSuccess is true)
                {
                    var actionMethod = nameof(ConfirmEmail);
                    var controller = "Authentication";
                    object responseObject = new { accessToken.Response.Token, registerUserDto.Email };

                    var confirmationLink = Url.Action(actionMethod, controller, responseObject, Request.Scheme);

                    var message = new Message(new string[] {
                    registerUserDto.Email! },
                        "Confirmation email link",
                        confirmationLink!);

                    var isSendEmailSuccessfull = _emailService.SendEmails(message);

                    if (isSendEmailSuccessfull is true)
                    {
                        return StatusCode(StatusCodes.Status200OK,
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

                if (confirmEmail.Succeeded)
                {
                    return StatusCode(StatusCodes.Status200OK,
                        new ResponseDto
                        {
                            Status = "Success",
                            Message = $"Email: {email} verified successfully.",
                            IsSuccess = true
                        });
                }
            }

            return StatusCode(StatusCodes.Status500InternalServerError,
                    new ResponseDto
                    {
                        Status = "Error",
                        Message = $"User with Email: {email} does not exist.",
                        IsSuccess = false
                    });
        }

        [HttpPost("login-user")]
        public async Task<IActionResult> Login([FromBody] LoginRequestDto loginRequestDto)
        {
            var oPT2FactorResponse = await _userMgmtService.GetOTPByLoginAsync(loginRequestDto);

            if (oPT2FactorResponse.Response is not null)
            {
                var user = oPT2FactorResponse.Response.User;

                if (user.TwoFactorEnabled is true)
                {
                    var twoFToken = oPT2FactorResponse.Response.TwoFToken;

                    var message = new Message(
                        new string[] { user.Email! },
                        "OTP Email Confirmation",
                        twoFToken);

                    _emailService.SendEmails(message);

                    return StatusCode(StatusCodes.Status200OK,
                        new ResponseDto
                        {
                            Status = "Success",
                            Message = $"An Email has been sent to: {user.Email} to perform an OTP (2 factor Authentication.) .",
                            IsSuccess = oPT2FactorResponse.IsSuccess
                        });
                }

                //checking user's password
                var passwordExist = await _userManager.CheckPasswordAsync(user, loginRequestDto.Password);

                if (user is not null && passwordExist is true)
                {
                    var jwtToken = await _userMgmtService.GetJwtTokenAsync(user);

                    return Ok(jwtToken);
                }
            }

            //if user not exist, we're returning an Unauthorized result
            return Unauthorized();
        }

        [HttpPost("login-2F")]
        public async Task<IActionResult> Login2FactorAuthn(string twoFToken, string username)
        {
            var loginUser = await _userMgmtService.LoginUserWith2FTokenAsnyc(twoFToken, username);

            if (loginUser.IsSuccess is true)
            {
                return Ok(loginUser);
            }

            return StatusCode(StatusCodes.Status404NotFound,
                new ResponseDto
                {
                    Status = "Error",
                    Message = $"An invalid OTP (2 factor Token.)",
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
                var passwordResetToken = await _userManager.GeneratePasswordResetTokenAsync(user);
                string actionMethod = nameof(ResetPassword);
                string controller = "Authentication";
                object objectValue = new { passwordResetToken, email = user.Email };

                var forgotPasswordLink = Url.Action(
                    actionMethod,
                    controller,
                    objectValue,
                    Request.Scheme
                );

                IEnumerable<string> emailTo = new string[] { user.Email };

                var subject = "Forgot Passsword Link:";

                var message = new Message(emailTo, subject, forgotPasswordLink!);

                var isEmailSent =_emailService.SendEmails(message);

                if (isEmailSent is true)
                {
                    return StatusCode(StatusCodes.Status200OK,
                    new ResponseDto
                    {
                        Status = "Success",
                        Message = $"Password reset request link is sent to: {email}.",
                        IsSuccess = true
                    });
                }

                return StatusCode(StatusCodes.Status200OK,
                    new ResponseDto
                    {
                        Status = "Error",
                        Message = $"Failed to send an email to: {email}.",
                        IsSuccess = false
                    });
            }

            return StatusCode(StatusCodes.Status404NotFound,
                new ResponseDto
                {
                    Status = "Error",
                    Message = $"User's email: {email} not found in system.",
                    IsSuccess = false
                });
        }


        [HttpGet("reset-password")]
        public async Task<IActionResult> ResetPassword(string passwordResetToken, string email)
        {
            var resetPasswordModel = new ResetPasswordDto { Token = passwordResetToken, Email = email };

            return Ok(new { resetPasswordModel });
        }


        [HttpPost]
        [Route("reset-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword(ResetPasswordDto resetPasswordDto)
        {
            var user = await _userManager.FindByEmailAsync(resetPasswordDto.Email);

            if (user is not null)
            {
                var resetPasswordResult = await _userManager.ResetPasswordAsync(user, resetPasswordDto.Token, resetPasswordDto.Password);

                if (resetPasswordResult.Succeeded is false)
                {
                    foreach (var error in resetPasswordResult.Errors)
                    {
                        ModelState.AddModelError(error.Code, error.Description);
                    }

                    return Ok(ModelState);
                }

                return StatusCode(StatusCodes.Status200OK,
                    new ResponseDto
                    {
                        Status = "Success",
                        Message = $"Password is reset/changed.",
                        IsSuccess = true
                    });
            }

            return StatusCode(StatusCodes.Status404NotFound,
                new ResponseDto
                {
                    Status = "Error",
                    Message = $"User with Email not found. Password reset failed.",
                    IsSuccess = false
                });
        }

    }

}
