using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace WebApplication1.Models
{
	public class Users
	{
		public string Id { get; set; }
		public string Name { get; set; }

		public string Email { get; set; }

		public string Phone { get; set; }

		public string Password { get; set; }

		public string Role { get; set; }

		public string Status { get; set; }


	}
}