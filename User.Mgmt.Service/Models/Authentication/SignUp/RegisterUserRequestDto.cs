using System.ComponentModel.DataAnnotations;

namespace User.Mgmt.Service.Models.Authentication.SignUp
{
    public class RegisterUserRequestDto
    {
        [Required(ErrorMessage = "Username is Required.")]
        public string Username { get; set; } = string.Empty;

        [Required(ErrorMessage = "Email is required.")]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "Password is required.")]
        public string Password { get; set; } = string.Empty;

        [Required(ErrorMessage = "Role is required.")]
        public List<string>? Roles { get; set; } = new List<string>();
    }
}
