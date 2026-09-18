namespace User.Mgmt.Service.Models
{
    public class APIResponseDto<T>
    {
        public bool IsSuccess { get; set; } = false;
        public string Message { get; set; }= string.Empty;
        public int StatusCode { get; set; }
        public T? Response { get; set; }
    }
}
