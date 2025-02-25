using System.ComponentModel.DataAnnotations;

namespace SportifyX.Application.DTOs.User
{
    public class ChangePasswordDto
    {
        [Required(ErrorMessage = "Email is required.")]
        [EmailAddress(ErrorMessage = "Invalid email format.")]
        public required string Email { get; set; }

        [Required(ErrorMessage = "Current Password is required.")]
        [MinLength(6, ErrorMessage = "Current Password must be at least 6 characters long.")]
        public required string CurrentPassword { get; set; }

        [Required(ErrorMessage = "New Password is required.")]
        [MinLength(6, ErrorMessage = "New Password must be at least 6 characters long.")]
        public required string NewPassword { get; set; }

        [Required(ErrorMessage = "Confirm New Password is required.")]
        [Compare("NewPassword", ErrorMessage = "New Passwords do not match.")]
        public required string ConfirmNewPassword { get; set; }
    }
}
