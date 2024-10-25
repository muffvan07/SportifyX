using System.ComponentModel.DataAnnotations;

namespace SportifyX.Application.DTOs.User
{
    public class ConfirmMobileVerificationDto
    {
        [Required]
        public Guid UserId { get; set; }

        [Required]
        public string CountryCode { get; set; }

        [Required]
        public string MobileNumber { get; set; }

        [Required]
        public string VerificationCode { get; set; }
    }
}
