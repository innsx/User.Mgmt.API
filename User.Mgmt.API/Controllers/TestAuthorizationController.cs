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

        [Authorize(Roles = "User")]
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
