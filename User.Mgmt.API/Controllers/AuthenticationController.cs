using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using User.Mgmt.API.Models;
using User.Mgmt.API.Models.SignUp;
using User.Mgmt.Service.Models;
using User.Mgmt.Service.Services;

namespace User.Mgmt.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IEmailService _emailService;

        public AuthenticationController(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager, IEmailService emailService)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _emailService = emailService;
        }

        [HttpPost("register-user")]
        public async Task<IActionResult> Register([FromBody] RegisterUserDto registerUserDto, string role)
        {
            //check user exists in DB
            var userExists = await _userManager.FindByEmailAsync(registerUserDto.Email);

            if (userExists is not null)
            {
                return StatusCode(StatusCodes.Status403Forbidden,
                                new ResponseDto
                                {
                                    Status = "Error",
                                    Message = "User already exits."
                                });
            }

            // instantiate an IdentityUser and populate registerUserDto values
            IdentityUser user = new()
            {
                Email = registerUserDto.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = registerUserDto.Username
            };


            //check if pass-in role exists
            var isRoleExists = await _roleManager.RoleExistsAsync(role);

            //if role exists
            if (isRoleExists is true)
            {
                //create user
                var createUser = await _userManager.CreateAsync(user, registerUserDto.Password);

                if (!createUser.Succeeded)
                {
                    return StatusCode(StatusCodes.Status500InternalServerError,
                    new ResponseDto
                    {
                        Status = "Error",
                        Message = "Failed to created User."
                    });
                }

                //add role to user on AspNetUserRoles table
                await _userManager.AddToRoleAsync(user, role);

                //Generate a Token for User with this email
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);

                //create a confirmationLink based of a Url.Action
                var confirmationLink = Url.Action
                (
                    nameof(ConfirmEmail), //Endpoint in AuthenticationController.cs
                    "Authentication", //"Authentication" Controller
                    new { token, email = user.Email },
                    Request.Scheme  //invoke HTTPRequest Scheme
                );

                //create a message consists of user's email, subject and the confirmationLink
                var message = new Message
                (
                    new string[] { user.Email!},
                    "Confirmation email link",
                    confirmationLink!
                );
                
                //then send message with User's email
                _emailService.SendEmails(message);

                return StatusCode(StatusCodes.Status200OK,
                new ResponseDto
                {
                    Status = "Success",
                    Message = $"User created and Email is sent to {user.Email} successfully."
                });
            }
            else
            {
                return StatusCode(StatusCodes.Status500InternalServerError,
                new ResponseDto
                {
                    Status = "Error",
                    Message = $"Role: {role} does not exist."
                });
            }
        }

        [HttpGet("confirm-email")]
        public async Task<IActionResult> ConfirmEmail(string token, string email)
        {
            var user = await _userManager.FindByEmailAsync(email);

            if (user is not null)
            {
                var confirmEmail = await _userManager.ConfirmEmailAsync(user, token);

                if (confirmEmail.Succeeded)
                {
                    return StatusCode(StatusCodes.Status200OK,
                        new ResponseDto
                        {
                            Status = "Success",
                            Message = $"Email: {email} verified successfully."
                        });
                }
            }

            return StatusCode(StatusCodes.Status500InternalServerError,
                new ResponseDto
                {
                    Status = "Error",
                    Message = $"User with Email: {email} does not exist."
                });
        }
    }
    
}
