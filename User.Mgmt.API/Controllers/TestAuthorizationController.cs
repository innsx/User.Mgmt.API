using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using User.Mgmt.Service.Services;

namespace User.Mgmt.API.Controllers
{

    [Route("api/[controller]")]
    [ApiController]
    public class TestAuthorizationController : ControllerBase
    {
        private readonly IRedisCacheService _redisCacheService;

        public TestAuthorizationController(IRedisCacheService redisCacheService)
        {
            _redisCacheService = redisCacheService;
        }

        [Authorize(Roles = "Admin")]
        [HttpGet("employees")]
        public IEnumerable<string> GetEmployees()
        {
            _redisCacheService.SetData("employees", new List<string> { "Admin", "Jon", "Sue", "Julie" }, DateTimeOffset.Now.AddMinutes(10));
            
            return new List<string> {"Admin", "Jon", "Sue", "Julie" };
        }

        //in Program.cs if setup with:  options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
        [Authorize(Roles = "User")]  //use this setup         
        //[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme, Roles = "User")] //else use this setup
        [HttpGet("employee-by-id")]
        public IActionResult GetEmployeeById()
        {
            _redisCacheService.SetData("UserEmployee", "User Jon Doe", DateTimeOffset.Now.AddMinutes(10));

            return Ok("User Jon Doe");
        }

        [Authorize(Roles = "HR")]
        [HttpGet("get-employee")]
        public IActionResult GetEmployee()
        {
            _redisCacheService.SetData("HREmployee", "HR Jon Doe", DateTimeOffset.Now.AddMinutes(10));
            return Ok("HR Jon Doe");
        }

        [Authorize(Roles = "Guest")]
        [HttpGet("get-Guest-employee")]
        public IActionResult GetGuestEmployee()
        {
            _redisCacheService.SetData("GuestEmployee", "Guest Jon Doe", DateTimeOffset.Now.AddMinutes(10));

            return Ok("Guest Jon Doe");
        }
    }
}
