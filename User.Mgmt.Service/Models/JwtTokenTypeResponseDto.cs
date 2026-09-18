namespace User.Mgmt.Service.Models
{
    public class JwtTokenTypeResponseDto
    {
        public string? TokenContext { get; set; }
        public DateTime ExpiryTokenDate { get; set; }
    }
}
