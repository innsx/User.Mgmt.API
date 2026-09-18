namespace User.Mgmt.Service.Models.Authentication.UserResponse
{
    public class LoginResponseDto
    {
        public JwtTokenTypeResponseDto AccessToken { get; set; } = null!;
        public JwtTokenTypeResponseDto? RefreshToken { get; set; } = null!;
    }
}
