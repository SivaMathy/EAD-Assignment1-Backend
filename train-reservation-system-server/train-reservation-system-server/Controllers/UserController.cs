using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using MongoDB.Driver;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using WebApplication1.Models;
using System.Net;
using System.Net.Mail;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace WebApplication1.Controllers
{
    [Route("api/[controller]")]
    public class UserController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        //private readonly JwtAuthenticationService _jwtAuthenticationService;
        private readonly IMongoCollection<Users> _userCollection;
        public UserController(IConfiguration configuration)
        {
            _configuration = configuration;
            // _jwtAuthenticationService = jwtAuthenticationService;
            var dbClient = new MongoClient(_configuration.GetConnectionString("EmployeeAppCon"));
            var database = dbClient.GetDatabase("RedRails");
            _userCollection = database.GetCollection<Users>("Users");
        }

        [HttpGet]
        public JsonResult Get()
        {
            MongoClient dbClient = new MongoClient(_configuration.GetConnectionString("EmployeeAppCon"));

            var dbList = dbClient.GetDatabase("RedRails").GetCollection<Users>("Users").AsQueryable();

            return new JsonResult(dbList);
        }

        [HttpPost]
        public JsonResult Post([FromBody] Users dep)
        {
            MongoClient dbClient = new MongoClient(_configuration.GetConnectionString("EmployeeAppCon"));

            dbClient.GetDatabase("RedRails").GetCollection<Users>("Users").InsertOne(dep);

            SendWelcomeEmail(dep);

            return new JsonResult("Added Successfully");
        }

        [HttpPut("{id}")]
        public JsonResult Put(Users dep, string id)
        {
            MongoClient dbClient = new MongoClient(_configuration.GetConnectionString("EmployeeAppCon"));

            var filter = Builders<Users>.Filter.Eq("Id", id);

            var update = Builders<Users>.Update.Set("Name", dep.Name)
                .Set("Email", dep.Email)
                .Set("Phone", dep.Phone)
                .Set("Password", dep.Password)
                .Set("Role", dep.Role)
                .Set("Status", dep.Status);

            dbClient.GetDatabase("RedRails").GetCollection<Users>("Users").UpdateOne(filter, update);

            return new JsonResult("Updated Successfully");
        }

        [HttpDelete("{id}")]
        public JsonResult Delete(string id)
        {
            MongoClient dbClient = new MongoClient(_configuration.GetConnectionString("EmployeeAppCon"));

            var filter = Builders<Users>.Filter.Eq("Id", id);

            dbClient.GetDatabase("RedRails").GetCollection<Users>("Users").DeleteOne(filter);

            return new JsonResult("Deleted Successfully");
        }

        [HttpGet("{id}")]
        public JsonResult GetById(string id)
        {
            MongoClient dbClient = new MongoClient(_configuration.GetConnectionString("EmployeeAppCon"));

            var filter = Builders<Users>.Filter.Eq("Id", id);

            var user = dbClient.GetDatabase("RedRails").GetCollection<Users>("Users").Find(filter).FirstOrDefault();

            return new JsonResult(user);
        }

        private void SendWelcomeEmail(Users user)
        {

            var smtpClient = new SmtpClient
            {
                Host = "smtp.gmail.com",
                Port = 587,
                Credentials = new NetworkCredential("nishannisha330@gmail.com", "vwrgqcedozekvjnc"),
                EnableSsl = true,
            };

            // Create a new email message
            var message = new MailMessage
            {
                From = new MailAddress("nishannisha330@gmail.com"),
                Subject = "Welcome to Our Website",
                Body = $"Hello {user.Name},\n\nWelcome to RedRails!\n\nThis is your password:- {user.Password}\n\nThank you for reaching us.",
            };

            message.To.Add(user.Email);

            // Send the email
            smtpClient.Send(message);

        }
        [HttpPost("login")]
        public IActionResult Login([FromBody] LoginRequest loginRequest)
        {
            var users = _userCollection.Find(u => u.Id == loginRequest.Id).FirstOrDefault();

            if (users != null && users.Password == loginRequest.Password)
            {
                // Generate JWT token
                var token = GenerateJwtToken(users);

                // Return token to the client
                return Ok(new { Token = token });
            }
            return BadRequest();

        }

        [HttpGet("protected")]
        [Authorize] // Requires a valid JWT token
        public IActionResult Protected()
        {
            // This endpoint is protected and can only be accessed with a valid JWT token.
            // The user's identity is available through the User property.
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            return Ok(new { Message = $"Protected endpoint accessed by user with ID: {userId}" });
        }

        private string GenerateJwtToken(Users user)
        {
            var secretKey = _configuration["JwtSettings:SecretKey"];
            var issuer = _configuration["JwtSettings:Issuer"];
            var audience = _configuration["JwtSettings:Audience"];
            var expirationMinutes = 30.0; // Set the expiration time to 30 minutes manually


            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        new Claim("Status", user.Status),     // Add user status as a claim
        new Claim("Role", user.Role)
            };

            var token = new JwtSecurityToken(
                issuer,
                audience,
                claims,
                expires: DateTime.UtcNow.AddMinutes(expirationMinutes),
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

    }
}
