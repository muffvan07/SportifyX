using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SportifyX.Application.ResponseModels.User
{
    public class AddRoleResponseModel
    {
        public Guid UserId { get; set; }
        public string Username { get; set; }
        public string RoleName { get; set; }
        public DateTime RoleAssignedDate { get; set; }
    }

}
