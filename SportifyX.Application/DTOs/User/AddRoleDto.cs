using System.ComponentModel.DataAnnotations;
using System;
using SportifyX.Application.DTOs.Attributes;

namespace SportifyX.Application.DTOs.User
{
    public class AddRoleDto
    {
        [Required(ErrorMessage = "User Id is required.")]
        [NotEmptyGuid(ErrorMessage = "User Id cannot be an empty GUID.")]
        public Guid UserId { get; set; }

        [Required(ErrorMessage = "Current User Id is required.")]
        [NotEmptyGuid(ErrorMessage = "Current User Id cannot be an empty GUID.")]
        public Guid CurrentUserId { get; set; }

        [Required(ErrorMessage = "Role Name is required.")]
        [MinLength(3, ErrorMessage = "Role Name must be at least 3 characters long.")]
        [MaxLength(50, ErrorMessage = "Role Name cannot be longer than 50 characters.")]
        public string RoleName { get; set; } = string.Empty;
    }
}
