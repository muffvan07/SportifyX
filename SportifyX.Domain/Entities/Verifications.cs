using System.ComponentModel.DataAnnotations;

namespace SportifyX.Domain.Entities
{
    public class Verifications
    {
        [Key]
        public required Guid VerificationId { get; set; }
        public required Guid UserId { get; set; }
        public string Email { get; set; } = string.Empty;
        public string PhoneNumber { get; set; } = string.Empty;
        public required string VerificationType { get; set; }
        public required string Token { get; set; }
        public DateTime ExpirationDate { get; set; }
        public bool IsUsed { get; set; }
        public DateTime CreatedDate { get; set; }
        public DateTime? LastModifiedDate { get; set; }
        public required string Status { get; set; }
    }
}
