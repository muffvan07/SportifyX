using System.ComponentModel.DataAnnotations;

namespace SportifyX.Application.DTOs.User
{
    public class InitiateMobileVerificationDto
    {
        [Required]
        public Guid UserId { get; set; }

        [Required]
        public string CountryCode { get; set; }

        [Required]
        public string MobileNumber { get; set; }
    }
}
