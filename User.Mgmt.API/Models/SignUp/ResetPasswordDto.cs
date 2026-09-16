using System.ComponentModel.DataAnnotations;

namespace User.Mgmt.API.Models.SignUp
{
    public class ResetPasswordDto
    {
        [Required]
        public string Password { get; set; } = null!;

        [Compare("Password", ErrorMessage = "The Password and confirmation password do not matched.")]
        public string ConfirmPassword { get; set; } = null!;

        public string Email { get; set; } = null!;
        public string Token { get; set; }= null!;
    }
}
