namespace Nexora.Core;

/// <summary>Техническое доказательство: откуда взято значение и что именно прочитано.</summary>
/// <param name="Source">Источник, например «WMI ROOT\cimv2: Win32_OperatingSystem.BuildNumber».</param>
/// <param name="Detail">Прочитанное значение или фрагмент.</param>
public sealed record Evidence(string Source, string Detail)
{
    public string Source { get; } = Require(Source, nameof(Source));
    public string Detail { get; } = Detail ?? "";

    private static string Require(string value, string name) =>
        string.IsNullOrWhiteSpace(value) ? throw new ArgumentException("Источник данных обязателен.", name) : value;
}
