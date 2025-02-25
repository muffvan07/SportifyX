using SportifyX.Domain.Entities.BaseModel;
using System.ComponentModel.DataAnnotations;

namespace SportifyX.Domain.Entities
{
    public class PasswordRecoveryToken : BaseObjectModel
    {
        [Key]
        public long Id { get; set; }
        public long UserId { get; set; }
        public required string Token { get; set; }
        public DateTime Expiration { get; set; }
        public bool IsUsed { get; set; }
    }
}
