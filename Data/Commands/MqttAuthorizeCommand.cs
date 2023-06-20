namespace MQTT_Authentication_Server.Data.Commands
{
    public class MqttAuthorizeCommand
    {
        public string? Username { get; set; }
        public string? ClientId { get; set; }
        public string? Broker { get; set; }
        public string? Ip { get; set; }
        public string? Topic { get; set; }
        public string? Action { get; set; }
    }
}
