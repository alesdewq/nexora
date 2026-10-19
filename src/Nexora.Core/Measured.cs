namespace Nexora.Core;

/// <summary>
/// Значение, которое могло быть не получено. Нет неявного «0 по умолчанию»: недоступность — отдельное состояние с причиной.
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1000",
    Justification = "Фабрики Measured<T>.Of/Unavailable — основной способ создания; вывод типа здесь не нужен.")]
public readonly struct Measured<T> : IEquatable<Measured<T>>
{
    public const string UnavailableText = "данные недоступны";

    private readonly T? _value;

    private Measured(T? value, bool available, string source, string? reason)
    {
        _value = value;
        IsAvailable = available;
        Source = source;
        Reason = reason;
    }

    public bool IsAvailable { get; }
    public string Source { get; }
    /// <summary>Причина недоступности (null, если значение получено).</summary>
    public string? Reason { get; }

    public T Value => IsAvailable ? _value! : throw new InvalidOperationException($"Значение недоступно: {Reason}");

    public static Measured<T> Of(T value, string source)
    {
        ArgumentNullException.ThrowIfNull(value);
        ArgumentException.ThrowIfNullOrWhiteSpace(source);
        return new(value, true, source, null);
    }

    public static Measured<T> Unavailable(string source, string reason)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(source);
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);
        return new(default, false, source, reason);
    }

    public bool TryGetValue(out T value)
    {
        value = _value!;
        return IsAvailable;
    }

    public string Format(Func<T, string>? format = null) =>
        IsAvailable ? (format ?? (v => v!.ToString() ?? ""))(_value!) : UnavailableText;

    public override string ToString() => Format();

    public bool Equals(Measured<T> other) =>
        IsAvailable == other.IsAvailable && Source == other.Source && Reason == other.Reason
        && EqualityComparer<T?>.Default.Equals(_value, other._value);

    public override bool Equals(object? obj) => obj is Measured<T> m && Equals(m);
    public override int GetHashCode() => HashCode.Combine(IsAvailable, Source, Reason, _value);
    public static bool operator ==(Measured<T> a, Measured<T> b) => a.Equals(b);
    public static bool operator !=(Measured<T> a, Measured<T> b) => !a.Equals(b);
}
