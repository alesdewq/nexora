using System.Reflection;

namespace Nexora.Core;

public static class Product
{
    public const string Name = "NEXORA";

    public static string Version { get; } =
        typeof(Product).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0]
        ?? "0.0.0";
}
