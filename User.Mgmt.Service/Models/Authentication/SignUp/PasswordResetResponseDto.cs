namespace User.Mgmt.Service.Models.Authentication.SignUp
{
    public class PasswordResetResponseDto
    {
        public string Email { get; set; } = null!;
        public string PasswordResetToken { get; set; } = null!;
    }
}
