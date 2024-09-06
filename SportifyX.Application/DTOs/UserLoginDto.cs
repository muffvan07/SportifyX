using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SportifyX.Application.DTOs
{
    public class UserLoginDto
    {
        public string? Email { get; set; }
        public required string Password { get; set; }
    }
}
