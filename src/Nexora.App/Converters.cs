using System.Globalization;
using System.Windows;
using System.Windows.Data;
using Nexora.Core;

namespace Nexora.App;

/// <summary>Показывать элемент только в указанных разделах: ConverterParameter="Performance,Users".</summary>
public sealed class SectionVisibilityConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is Section s && parameter is string p && p.Split(',').Any(x => Enum.TryParse<Section>(x.Trim(), out var v) && v == s)
            ? Visibility.Visible : Visibility.Collapsed;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}

/// <summary>Скрывать пустые строки и null. ConverterParameter="invert" — наоборот.</summary>
public sealed class EmptyToCollapsedConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var empty = value is null || (value is string s && string.IsNullOrWhiteSpace(s)) || (value is bool b && !b) || (value is int i && i == 0);
        if (parameter as string == "invert") empty = !empty;
        return empty ? Visibility.Collapsed : Visibility.Visible;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}
