﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SportifyX.Application.DTOs
{
    public class ConfirmEmailDto
    {
        public Guid UserId { get; set; }
        public required string ConfirmationCode { get; set; }
    }
}
