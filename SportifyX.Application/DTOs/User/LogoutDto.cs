using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SportifyX.Application.DTOs.User
{
    public class LogoutDto
    {
        [Required(ErrorMessage = "User Id is required.")]
        public Guid UserId { get; set; }

        [Required(ErrorMessage = "Token is required.")]
        public required string Token { get; set; }
    }
}
