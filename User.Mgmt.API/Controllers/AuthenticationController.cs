using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using User.Mgmt.API.Models;
using User.Mgmt.API.Models.Login;
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
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly IEmailService _emailService;
        private readonly IConfiguration _configuration;

        public AuthenticationController(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager, IEmailService emailService, IConfiguration configuration, SignInManager<IdentityUser> signInManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _emailService = emailService;
            _configuration = configuration;
            _signInManager = signInManager;
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

            // instantiate an IdentityUser; assign registerUserDto values to its properties
            IdentityUser user = new()
            {
                Email = registerUserDto.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = registerUserDto.Username,
                TwoFactorEnabled = true
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
                    nameof(ConfirmEmail), //callBack Endpoint in AuthenticationController.cs
                    "Authentication", //"Authentication" Controller
                    new { token, email = user.Email },
                    Request.Scheme  //invoke HTTPRequest Scheme
                );

                //create a message consists of user's email, subject and the confirmationLink
                var message = new Message
                (
                    new string[] { user.Email! },
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
                //this line confirm User’s Email and UPDATE AspNetUser table EmailConfirmed column to a ‘1’ for TRUE
                //and the User is assigned  with the Registered Role in AspNetUserRoles table
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

        [HttpPost("login-user")]
        public async Task<IActionResult> Login([FromBody] LoginRequestDto loginRequestDto)
        {
            //checking user exists
            var user = await _userManager.FindByNameAsync(loginRequestDto.Username);

            if (user.TwoFactorEnabled is true)
            {
                //first sign-out current user
                await _signInManager.SignOutAsync();

                //re-sign-in User with loginRequestDto.Password
                await _signInManager.PasswordSignInAsync(user, loginRequestDto.Password, false, false);

                var twoFToken = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");

                var message = new Message(new string[] { user.Email! }, "OTP Confirmation", twoFToken);

                _emailService.SendEmails(message);

                return StatusCode(StatusCodes.Status200OK,
                    new ResponseDto
                    {
                        Status = "Success",
                        Message = $"An Email has been sent to: {user.Email} to perform an OTP (2 factor Authentication.) ."
                    });
            }

            //checking user's password
            var passwordExist = await _userManager.CheckPasswordAsync(user, loginRequestDto.Password);

            if (user is not null && passwordExist is true)
            {
                //creating a List of Claims
                var authClaims = new List<Claim>()
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                };

                //getting userRole
                var userRoles = await _userManager.GetRolesAsync(user);

                //adding roles to list of Claims
                foreach (var role in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, role));
                }

                //generating a token with Claims
                var jwtToken = GenerateToken(authClaims);

                return Ok(new //creating anynoymous object & return this object
                {
                    accessToken = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                    expiration = jwtToken.ValidTo
                });
            }

            //if user not exist, we're returning an Unauthorized result
            return Unauthorized();
        }

        [HttpPost("login-2F")]
        public async Task<IActionResult> Login2FactorAuthn(string twoFToken, string username)
        {
            var user = await _userManager.FindByNameAsync(username);

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
                    var authClaims = new List<Claim>()
                    {
                        new Claim(ClaimTypes.NameIdentifier, username),
                        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                    };

                    var userRoles = await _userManager.GetRolesAsync(user);

                    foreach (var role in userRoles)
                    {
                        authClaims.Add(new Claim(ClaimTypes.Role, role));
                    }

                    var jwtToken = GenerateToken(authClaims);

                    return Ok(new
                    {
                        token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                        expiration = jwtToken.ValidTo
                    });
                }
            }

            return StatusCode(StatusCodes.Status404NotFound,
            new ResponseDto
                    {
                        Status = "Error",
                        Message = $"User provided an invalid Two Factor Authentication code."
                    });
        }

        private JwtSecurityToken GenerateToken(List<Claim> authClaims)
        {
            var secretKey = Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]);
            var authSigningKey = new SymmetricSecurityKey(secretKey);

            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: DateTime.Now.AddHours(3),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
            );

            return token;
        }
    }

}
