namespace MQTT_Authentication_Server.Data.Commands
{
    public class MqttLoginCommand
    {
        public string? Username { get; set; }
        public string? Password { get; set; }
        public string? ClientId { get; set; }

    }
}
