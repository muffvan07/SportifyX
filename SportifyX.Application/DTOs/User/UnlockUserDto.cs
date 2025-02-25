namespace SportifyX.Application.DTOs.User
{
    public class UnlockUserDto
    {
        public required long AdminUserId { get; set; }
        public required string Email { get; set; }
    }
}
