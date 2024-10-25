using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SportifyX.Application.ResponseModels.User
{
    public class PasswordResetTokenResponseModel
    {
        public string Token { get; set; }
        public DateTime Expiration { get; set; }  // Added expiration time
    }
}
