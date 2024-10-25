namespace SportifyX.Application.DTOs.User
{
    public class InitiateEmailVerificationDto
    {
        public Guid UserId { get; set; }
        public string Email { get; set; } = string.Empty;
    }
}
