using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SportifyX.Application.DTOs
{
    public class LogoutDto
    {
        public Guid UserId { get; set; }
        public required string Token { get; set; }
    }
}
