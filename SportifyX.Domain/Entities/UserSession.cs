using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SportifyX.Domain.Entities
{
    public class UserSession
    {
        [Key]
        public Guid Id { get; set; }
        public Guid UserId { get; set; }
        public required string Token { get; set; }
        public DateTime Expiration { get; set; }
        public bool IsValid { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.Now;
    }
}
