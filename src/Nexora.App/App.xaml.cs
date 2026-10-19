using System.Windows;
using Nexora.App.ViewModels;
using Nexora.App.Views;

namespace Nexora.App;

public partial class App : Application
{
    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        if (e.Args.Contains("--scan"))
        {
            Shutdown(await CliScan.RunAsync(e.Args));
            return;
        }

        var smoke = Array.IndexOf(e.Args, "--smoke-test");
        if (smoke >= 0)
        {
            var outDir = e.Args.Length > smoke + 1 && !e.Args[smoke + 1].StartsWith("--", StringComparison.Ordinal) ? e.Args[smoke + 1] : "smoke";
            Shutdown(await SmokeTest.RunAsync(outDir, e.Args.Contains("--with-scan"), e.Args.Contains("--demo")));
            return;
        }

        var vm = new MainViewModel(new WpfDialogs());
        var window = new MainWindow { DataContext = vm };

        MainWindow = window;
        window.Show();
    }
}
