namespace SportifyX.Application.DTOs.User
{
    public class ConfirmEmailVerificationDto
    {
        public long UserId { get; set; }
        public required string Email { get; set; }
        public string Token { get; set; } = string.Empty;
    }
}
