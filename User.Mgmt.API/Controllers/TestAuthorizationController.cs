using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace User.Mgmt.API.Controllers
{

    [Route("api/[controller]")]
    [ApiController]
    public class TestAuthorizationController : ControllerBase
    {
        [Authorize(Roles = "Admin")]
        [HttpGet("employees")]
        public IEnumerable<string> GetEmployees()
        {
            return new List<string> {"Admin", "Jon", "Sue", "Julie" };
        }

        //in Program.cs if setup with:  options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
        [Authorize(Roles = "User")]  //use this setup         
        //[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme, Roles = "User")] //else use this setup
        [HttpGet("employee-by-id")]
        public IActionResult GetEmployeeById()
        {
            return Ok("User Jon Doe");
        }

        [Authorize(Roles = "HR")]
        [HttpGet("get-employee")]
        public IActionResult GetEmployee()
        {
            return Ok("HR Jon Doe");
        }

        [Authorize(Roles = "Guest")]
        [HttpGet("get-Guest-employee")]
        public IActionResult GetGuestEmployee()
        {
            return Ok("Guest Jon Doe");
        }
    }
}
