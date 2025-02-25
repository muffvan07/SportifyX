using SportifyX.Domain.Entities.BaseModel;
using System.ComponentModel.DataAnnotations;

namespace SportifyX.Domain.Entities
{
    public class UserSession : BaseObjectModel
    {
        [Key]
        public long Id { get; set; }
        public long UserId { get; set; }
        public required string Token { get; set; }
        public DateTime Expiration { get; set; }
        public bool IsValid { get; set; }
    }
}
