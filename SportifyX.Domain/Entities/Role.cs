﻿using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SportifyX.Domain.Entities
{
    public class Role
    {
        [Key]
        public Guid Id { get; set; }
        public required string Name { get; set; }
        public string? NormalizedName { get; set; }
        public DateTime CreatedDate { get; set; }
    }
}
