using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SportifyX.Application.DTOs
{
    public class PasswordResetDto
    {
        public string? Email { get; set; }
        public required string NewPassword { get; set; }
    }
}
