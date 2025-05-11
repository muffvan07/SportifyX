using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SportifyX.Application.ResponseModels.User
{
    public class RegisteredUserResponseModel
    {
        public long UserId { get; set; }
        public string? Username { get; set; }
        public string? Email { get; set; }
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
        public string? PhoneNumber { get; set; }
        public DateTime? Dob { get; set; }
        public int Gender { get; set; }
        public DateTime CreationDate { get; set; }
        public bool IsEmailConfirmed { get; set; }
        public bool IsPhoneNumberConfirmed { get; set; }
        public List<string> Roles { get; set; } = [];
    }
}
