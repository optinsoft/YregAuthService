using Microsoft.AspNetCore.Mvc;
using YregAuthService.Requests;
using YregAuthService.Responses;

namespace YregAuthService.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class PasswordController : ControllerBase
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
                success = true,
                encrypted = PasswordManager.EncryptPassword(encryptRequest.password)
            });
        }
    }
}
