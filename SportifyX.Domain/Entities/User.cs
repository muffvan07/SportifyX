﻿using SportifyX.Domain.Entities.BaseModel;
using System.ComponentModel.DataAnnotations;

namespace SportifyX.Domain.Entities
{
    public class User : BaseObjectModel
    {
        [Key]
        public long Id { get; set; }
        public string FirstName { get; set; } = string.Empty;
        public string LastName { get; set; } = string.Empty;
        public string Username { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string PasswordHash { get; set; } = string.Empty;
        public string? SecurityStamp { get; set; }
        public string? PhoneNumber { get; set; }
        public DateTime DOB { get; set; }
        public int Gender { get; set; }
        public bool IsPhoneNumberConfirmed { get; set; }
        public bool IsEmailConfirmed { get; set; }
        public bool LockoutEnabled { get; set; }
        public int AccessFailedCount { get; set; }
        public DateTime? LockoutEndDateUtc { get; set; }
        public bool TwoFactorEnabled { get; set; }
        public List<UserRole>? UserRole { get; set; }
    }
}
