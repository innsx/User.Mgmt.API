using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace User.Mgmt.API.Controllers
{
    [Authorize(Roles = "Admin")]
    [Route("api/[controller]")]
    [ApiController]
    public class TestAuthorizationController : ControllerBase
    {
        [HttpGet("employees")]
        public IEnumerable<string> GetEmployees()
        {
            return new List<string> { "Jon", "Sue", "Julie" };
        }

        [HttpGet("employee-by-id")]
        public IActionResult GetEmployeeById()
        {
            return Ok("Jon Doe");
        }
    }
}
