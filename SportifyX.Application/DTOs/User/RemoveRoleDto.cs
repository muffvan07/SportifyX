using System.ComponentModel.DataAnnotations;

namespace SportifyX.Application.DTOs.User
{
    public class RemoveRoleDto
    {
        [Required(ErrorMessage = "User Id is required.")]
        public long UserId { get; set; }

        [Required(ErrorMessage = "Current User Id is required.")]
        public long CurrentUserId { get; set; }

        [Required(ErrorMessage = "Role Id is required.")]
        public long RoleId { get; set; }
    }
}
