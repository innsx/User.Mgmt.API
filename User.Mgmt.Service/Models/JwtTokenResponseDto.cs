namespace User.Mgmt.Service.Models
{
    public class JwtTokenResponseDto
    {
        public string? TokenContext { get; set; }
        public DateTime ExpiryTokenDate { get; set; }
    }
}
