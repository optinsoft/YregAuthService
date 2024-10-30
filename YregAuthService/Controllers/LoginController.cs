using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Text;
using System.Security.Cryptography;

namespace YregAuthService.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class LoginController : ControllerBase
    {
        private readonly string _jwt_key;
        private readonly string _jwt_issuer;
        private readonly string _jwt_expire_audience;
        private readonly int _jwt_expire_minutes;
        private readonly List<YregUser>? _users;
        public LoginController(IConfiguration config)
        {
            _jwt_key = config.GetValue<string>("Jwt:Key");
            _jwt_issuer = config.GetValue<string>("Jwt:Issuer");
            _jwt_expire_audience = config.GetValue<string>("Jwt:Audience");
            _jwt_expire_minutes = config.GetValue<int>("Jwt:ExpireMinutes");
            _users = config.GetSection("Users").Get<List<YregUser>>();
        }
        [HttpPost]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public ActionResult<LoginResponse> Post([FromBody] LoginRequest loginRequest)
        {
            //Find user with specified credentials
            var loginUser = _users?.Find(u => 
                u.Name != null &&
                u.Password != null &&
                String.Equals(u.Name, loginRequest.username, StringComparison.OrdinalIgnoreCase) && 
                PasswordManager.VerifyPassword(u.Password, loginRequest.password));
            if (loginUser == null)
            {
                return Unauthorized();
            }

            //If login usrename and password are correct then proceed to generate token
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt_key));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var Sectoken = new JwtSecurityToken(_jwt_issuer,
              _jwt_expire_audience,
              null,
              expires: DateTime.Now.AddMinutes(_jwt_expire_minutes),
              signingCredentials: credentials);

            return Ok(new LoginResponse
                {
                    token = new JwtSecurityTokenHandler().WriteToken(Sectoken)
                });
        }
    }
}
