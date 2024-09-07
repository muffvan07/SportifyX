using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SportifyX.Application.DTOs
{
    public class RemoveRoleDto
    {
        public Guid UserId { get; set; }
        public required string RoleName { get; set; }
    }
}
