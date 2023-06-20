using MQTT_Authentication_Server.Data;
using MQTT_Authentication_Server.Data.Commands;
using MQTT_Authentication_Server.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;


namespace MQTT_Authentication_Server.Controllers
{
    [Route("authorization/mqtt")]
    [AllowAnonymous]
    public class MqttAuthorizationController : BaseController
    {
        public MqttAuthorizationController(TCUContext tcuContext, UserManager<IdentityUser> userManager, IConfiguration config) : base(tcuContext, userManager, config)
        {

        }

        [HttpPost]
        [Route("authorize")]
        public IActionResult Authorize([FromBody] MqttAuthorizeCommand command)
        {
            string? clientId = command.ClientId;
            string? userName = command.Username;

            if (clientId == null)
                return Ok(new { result = "deny" });

            string? topic = command.Topic;
            string? action = command.Action;

            if (topic == null)
                return Ok(new { result = "deny" });
            if (action == null)
                return Ok(new { result = "deny" });

            // Servers can publish or subscribe to any topic they want
            if (clientId.StartsWith("Server"))
                Ok(new { result = "allow" });

            string deviceType = clientId.Split("-", 2)[0];
            string identifier = clientId.Split("-", 2)[1];

            switch (deviceType)
            {
                case "TCU":
                    identifier = identifier.Contains('/') ? identifier.Split("/")[0] : identifier;
                    long? tcuId = long.Parse(identifier);
                    Tcu? tcu = (from _tcu in tcuContext.Tcus
                                where _tcu.TcuId == tcuId
                                && _tcu.Username == userName
                                select _tcu).FirstOrDefault();

                    if (tcu == null)
                        return Ok(new { result = "deny" });

                    return AuthorizeTCU(tcu, topic, action);
                case "Mobile":
                    Device? device = (from _device in tcuContext.Devices
                                      where _device.DeviceId == identifier
                                      select _device).FirstOrDefault();
                    if (device == null)
                        return Ok(new { result = "deny" });
                    return AuthorizeMobile(device, topic, action);
                default:
                    return Ok(new { result = "deny" });
            }
        }

        private IActionResult AuthorizeTCU(Tcu tcu, string topic, string action)
        {

            bool isAuthorized = false;
            string[] topicParameters = topic.Split("/");
                if (action == "publish")
                {
                    // Any TCU can only publish to it's Events or server subscribed events
                    isAuthorized = topicParameters[0] == "TCU-" + tcu.TcuId.ToString();
                    isAuthorized = isAuthorized || (topicParameters[0] == "Server-TCU");
                }
                else if (action == "subscribe")
                {
                    // Any TCU can subscribe Only to it's events of devices connected to it
                    // or Server events that are for TCU
                    List<string> whiteList = (from _deviceTCU in tcuContext.DevicesTcus
                                              where _deviceTCU.TcuId == tcu.TcuId
                                              select "Mobile-" + _deviceTCU.DeviceId).ToList();
                    whiteList.Add("Server-TCU");
                    isAuthorized = whiteList.Contains(topicParameters[0]);
                }
            return Ok(new
            {
                result = isAuthorized ? "allow" : "deny"
            });
        }


        private IActionResult AuthorizeMobile(Device device, string topic, string action)
        {
            bool isAuthorized = false;
            string[] topicParameters = topic.Split("/");
                if (action == "publish")
                {
                    // Mobile Can only publish to it's events or server subscribed events
                    isAuthorized = topicParameters[0] == "Mobile-" + device.DeviceId;
                isAuthorized = isAuthorized || (topicParameters[0] == "Server-Mobile");
            }
                else if (action == "subscribe")
                {
                    // Any Mobile device can subscribe Only to it's TCU
                    // or Server events that are for Mobile devices
                    List<string> whiteList = (from _deviceTCU in tcuContext.DevicesTcus
                                              where _deviceTCU.DeviceId == device.DeviceId
                                              select "TCU-" + _deviceTCU.TcuId.ToString()).ToList();
                    whiteList.Add("Server-Mobile");
                    isAuthorized = whiteList.Contains(topicParameters[0]);
                }
            return Ok(new
            {
                result = isAuthorized ? "allow" : "deny"
            });
        }
    }
}
