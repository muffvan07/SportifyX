namespace SportifyX.Application.DTOs.User
{
    public class ConfirmEmailVerificationDto
    {
        public Guid UserId { get; set; }
        public required string Email { get; set; }
        public Guid Token { get; set; }
    }
}
