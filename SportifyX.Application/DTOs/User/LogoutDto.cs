using System.ComponentModel.DataAnnotations;

namespace SportifyX.Application.DTOs.User
{
    public class LogoutDto
    {
        [Required(ErrorMessage = "User Id is required.")]
        public long UserId { get; set; }

        [Required(ErrorMessage = "Token is required.")]
        public required string Token { get; set; }
    }
}
