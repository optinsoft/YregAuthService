using Microsoft.AspNetCore.Mvc;

namespace YregAuthService.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class PasswordController : Controller
    {
        [HttpPost("Encrypt")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public ActionResult<EncryptPasswordResponse> EncryptPassword([FromBody] EncryptPasswordRequest encryptRequest)
        {
            if (encryptRequest.password == null)
            {
                return BadRequest();
            }
            return Ok(new EncryptPasswordResponse
            {
                encrypted = PasswordManager.EncryptPassword(encryptRequest.password)
            });
        }
    }
}
