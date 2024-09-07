using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SportifyX.Domain.Entities
{
    public class UserRole
    {
        [Key]
        public Guid UserId { get; set; }
        public Guid RoleId { get; set; }
        public User? User { get; set; }
        public Role? Role { get; set; }
    }
}
