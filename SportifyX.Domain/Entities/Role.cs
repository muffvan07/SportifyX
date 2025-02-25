using SportifyX.Domain.Entities.BaseModel;
using System.ComponentModel.DataAnnotations;

namespace SportifyX.Domain.Entities
{
    public class Role : BaseObjectModel
    {
        [Key]
        public long Id { get; set; }
        public long RoleId { get; set; }
        public string Name { get; set; } = string.Empty;
        public string NormalizedName { get; set; } = string.Empty;
        public List<UserRole> UserRole { get; set; } = null!; // Many-to-Many Link
    }
}
