namespace Nexora.App.ViewModels;

/// <summary>Диалоги подтверждения и сохранения. В режиме smoke-теста подменяются заглушкой, которая всегда отвечает «нет».</summary>
public interface IDialogs
{
    bool Confirm(string title, string message);
    string? SaveFile(string defaultName, string filter);
    void Info(string title, string message);
}
