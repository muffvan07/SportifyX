using SportifyX.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SportifyX.Application.ResponseModels.User
{
    public class UserRoleResponseModel
    {
        public Guid UserId { get; set; }
        public List<UserRole> UserRoles { get; set; } = new List<UserRole>();
    }
}
