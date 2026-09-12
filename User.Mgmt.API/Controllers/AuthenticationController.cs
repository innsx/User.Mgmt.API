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
                        Message = "User failed to created."
                    });
                }

                //add role to user on AspNetUserRoles table
                await _userManager.AddToRoleAsync(user, role);

                return StatusCode(StatusCodes.Status201Created,
                new ResponseDto
                {
                    Status = "Success",
                    Message = "User created successfully."
                });
            }
            else
            {
                return StatusCode(StatusCodes.Status500InternalServerError,
                new ResponseDto
                {
                    Status = "Error",
                    Message = "Role does not exist."
                });
            }
        }

        [HttpGet("test-email")]
        public IActionResult TestEmail()
        {
            var subject = "Test...";
            var content = "<h1>Subscribe to my channel!";
            var to = new string[] { "kou20.xiong30@gmail.com" };
            
            //"need to turn verification on this account kou20.xiong21@gmail.com"

            var message = new Message(to, subject, content);

            _emailService.SendEmails(message);

            return StatusCode(StatusCodes.Status200OK,
            new ResponseDto
                    {
                        Status = "Success",
                        Message = "Email sent successfully."
                    });
        }
    }
}
