using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SportifyX.Application.DTOs
{
    public class PasswordRecoveryRequestDto
    {
        public required string Email { get; set; }
    }
}
