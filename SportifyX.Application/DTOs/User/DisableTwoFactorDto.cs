namespace SportifyX.Application.DTOs.User
{
    public class DisableTwoFactorDto
    {
        public long UserId { get; set; }
        public string Password { get; set; } = string.Empty; // Optional: for extra security
    }
}