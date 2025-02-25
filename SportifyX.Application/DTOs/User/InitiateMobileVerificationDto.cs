using System.ComponentModel.DataAnnotations;

namespace SportifyX.Application.DTOs.User
{
    public class InitiateMobileVerificationDto
    {
        [Required]
        public long UserId { get; set; }

        [Required]
        public string CountryCode { get; set; } = string.Empty;

        [Required]
        public string MobileNumber { get; set; } = string.Empty;
    }
}
