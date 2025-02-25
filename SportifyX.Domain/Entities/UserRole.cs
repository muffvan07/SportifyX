using SportifyX.Domain.Entities.BaseModel;
using System.ComponentModel.DataAnnotations;

namespace SportifyX.Domain.Entities
{
    public class UserRole : BaseObjectModel
    {
        [Key]
        public long Id { get; set; }
        public long UserId { get; set; }
        public long RoleId { get; set; }
        public User User { get; set; } = null!;
    }
}
