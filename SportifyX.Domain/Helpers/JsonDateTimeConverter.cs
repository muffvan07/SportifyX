using System.Text.Json;
using System.Text.Json.Serialization;

namespace SportifyX.Domain.Helpers
{
    public class JsonDateTimeConverter : JsonConverter<DateTime>
    {
        private const string DefaultFormat = "yyyy-MM-dd HH:mm:ss"; // Set your default format

        public override void Write(Utf8JsonWriter writer, DateTime value, JsonSerializerOptions options)
        {
            writer.WriteStringValue(value.ToString(DefaultFormat));
        }

        public override DateTime Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            return DateTime.Parse(reader.GetString()!); // Parse back to DateTime if needed
        }
    }
}
