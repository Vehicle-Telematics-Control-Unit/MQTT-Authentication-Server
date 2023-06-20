using MQTT_Authentication_Server.Data;
using MQTT_Authentication_Server.Data.Commands;
using MQTT_Authentication_Server.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace MQTT_Authentication_Server.Controllers
{
    [Route("authentication/mqtt")]
    public class MqttAuthenticationController : BaseController
    {
        public MqttAuthenticationController(TCUContext tcuContext, UserManager<IdentityUser> userManager, IConfiguration config) : base(tcuContext, userManager, config)
        {
        }

        [HttpPost]
        [Route("login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login([FromBody] MqttLoginCommand command)
        {
            string? clientId = command.ClientId;
            string? userName = command.Username;
            string? password = command.Password;

            if (clientId == null)
                return Ok(new
                {
                    result = "deny",
                    is_superuser = false
                });

            string deviceType = clientId.Split("-")[0];
            bool isValid = false;

            if (deviceType == "TCU")
            {
                clientId = clientId.Split("-")[1].Split("/")[0];
                isValid = (from _tcu in tcuContext.Tcus
                           where _tcu.TcuId == long.Parse(clientId)
                           && _tcu.Username == userName
                           && _tcu.Password == password
                           select _tcu).Any();
            }
            else if (deviceType == "Mobile")
            {
                IdentityUser user = await FindUser(userName);
                isValid = await userManager.CheckPasswordAsync(user, password);
            }

            string resultValue = isValid ? "allow" : "deny";
            return Ok(new
            {
                result = resultValue,
                is_superuser = false
            });
        }

        [HttpPost]
        [Route("getCredentials/TCU")]
        [Authorize(Policy = "TCUOnly")]
        public IActionResult GetTCUCredentials()
        {
            string? tcuMac = (from _claim in User.Claims
                              where _claim.Type == ClaimTypes.Name
                              select _claim.Value).FirstOrDefault();
            if (tcuMac == null)
                return Unauthorized();

            Tcu? tcu = (from _tcu in tcuContext.Tcus
                        where _tcu.Mac == tcuMac
                        select _tcu).FirstOrDefault();

            if (tcu == null)
                return Unauthorized();

            tcu.Username = GenerateRandomString();
            tcu.Password = GenerateRandomString();
            tcuContext.SaveChanges();

            return Ok(new
            {
                clientId = "TCU-" + tcu.TcuId.ToString(),
                userName = tcu.Username,
                password = tcu.Password
            });
        }
    }
}
