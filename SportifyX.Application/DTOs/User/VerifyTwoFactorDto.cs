namespace SportifyX.Application.DTOs.User
{
    public class VerifyTwoFactorDto
    {
        public long UserId { get; set; }
        public string VerificationCode { get; set; } = string.Empty;
    }
}