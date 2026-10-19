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

        var vm = new MainViewModel();
        var window = new MainWindow { DataContext = vm };

        var smoke = Array.IndexOf(e.Args, "--smoke-test");
        if (smoke >= 0)
        {
            var outDir = e.Args.Length > smoke + 1 ? e.Args[smoke + 1] : "smoke";
            Shutdown(await SmokeTest.RunAsync(window, vm, outDir));
            return;
        }

        MainWindow = window;
        window.Show();
    }
}
