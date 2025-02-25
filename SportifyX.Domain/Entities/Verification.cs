using SportifyX.Domain.Entities.BaseModel;
using System.ComponentModel.DataAnnotations;

namespace SportifyX.Domain.Entities
{
    public class Verification : BaseObjectModel
    {
        [Key]
        public long VerificationId { get; set; }
        public required long UserId { get; set; }
        public string Email { get; set; } = string.Empty;
        public string PhoneNumber { get; set; } = string.Empty;
        public required int VerificationType { get; set; }
        public required string Token { get; set; }
        public DateTime ExpirationDate { get; set; }
        public bool IsUsed { get; set; }
        public required int Status { get; set; }
    }
}
