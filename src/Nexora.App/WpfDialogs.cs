using System.Windows;
using Microsoft.Win32;
using Nexora.App.ViewModels;

namespace Nexora.App;

internal sealed class WpfDialogs : IDialogs
{
    public bool Confirm(string title, string message) =>
        MessageBox.Show(Application.Current.MainWindow, message, title, MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No) == MessageBoxResult.Yes;

    public string? SaveFile(string defaultName, string filter)
    {
        var d = new SaveFileDialog { FileName = defaultName, Filter = filter, AddExtension = true, OverwritePrompt = true };
        return d.ShowDialog(Application.Current.MainWindow) == true ? d.FileName : null;
    }

    public void Info(string title, string message) =>
        MessageBox.Show(Application.Current.MainWindow, message, title, MessageBoxButton.OK, MessageBoxImage.Information);
}

/// <summary>Для неинтерактивных запусков: ни одно действие не подтверждается, файлы не сохраняются.</summary>
internal sealed class DeclineAllDialogs : IDialogs
{
    public List<string> Asked { get; } = [];
    public bool Confirm(string title, string message) { Asked.Add(title); return false; }
    public string? SaveFile(string defaultName, string filter) => null;
    public void Info(string title, string message) { }
}
