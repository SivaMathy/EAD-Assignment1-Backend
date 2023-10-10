using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace WebApplication1.Models
{
    public class LoginRequest
    {
        public string Id { get; set; }
        public string Password { get; set; }
    }
}

