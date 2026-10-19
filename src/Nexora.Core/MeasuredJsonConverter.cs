using System.Text.Json;
using System.Text.Json.Serialization;

namespace Nexora.Core;

/// <summary>
/// JSON-представление <see cref="Measured{T}"/>: <c>{"value": …, "source": "…"}</c> или <c>{"unavailable": "причина", "source": "…"}</c>.
/// </summary>
public sealed class MeasuredJsonConverterFactory : JsonConverterFactory
{
    public override bool CanConvert(Type typeToConvert) =>
        typeToConvert.IsGenericType && typeToConvert.GetGenericTypeDefinition() == typeof(Measured<>);

    public override JsonConverter CreateConverter(Type typeToConvert, JsonSerializerOptions options) =>
        (JsonConverter)Activator.CreateInstance(
            typeof(MeasuredConverter<>).MakeGenericType(typeToConvert.GetGenericArguments()[0]))!;

    private sealed class MeasuredConverter<T> : JsonConverter<Measured<T>>
    {
        public override Measured<T> Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            if (reader.TokenType != JsonTokenType.StartObject) throw new JsonException("Ожидался объект Measured.");
            T? value = default;
            bool hasValue = false;
            string? source = null, reason = null;
            while (reader.Read() && reader.TokenType != JsonTokenType.EndObject)
            {
                var name = reader.GetString();
                reader.Read();
                switch (name)
                {
                    case "value": value = JsonSerializer.Deserialize<T>(ref reader, options); hasValue = value is not null; break;
                    case "source": source = reader.GetString(); break;
                    case "unavailable": reason = reader.GetString(); break;
                    default: reader.Skip(); break;
                }
            }
            source ??= "неизвестно";
            return hasValue ? Measured<T>.Of(value!, source) : Measured<T>.Unavailable(source, reason ?? "нет значения");
        }

        public override void Write(Utf8JsonWriter writer, Measured<T> value, JsonSerializerOptions options)
        {
            writer.WriteStartObject();
            if (value.TryGetValue(out var v))
            {
                writer.WritePropertyName("value");
                JsonSerializer.Serialize(writer, v, options);
            }
            else
            {
                writer.WriteString("unavailable", value.Reason ?? "нет значения");
            }
            writer.WriteString("source", value.Source ?? "неизвестно");
            writer.WriteEndObject();
        }
    }
}
