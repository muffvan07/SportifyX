using System.ComponentModel.DataAnnotations;

namespace SportifyX.Application.DTOs.User
{
    public class PasswordRecoveryRequestDto
    {
        [Required(ErrorMessage = "Email is required.")]
        [EmailAddress(ErrorMessage = "Invalid email format.")]
        public required string Email { get; set; }
    }
}
