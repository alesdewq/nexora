using System.IO;
using System.Security.Principal;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using Nexora.App.ViewModels;
using Nexora.App.Views;
using Nexora.Cleanup;
using Nexora.Core;
using Nexora.Platform;
using Nexora.Reporting;

namespace Nexora.App;

/// <summary>
/// Неинтерактивная проверка интерфейса: окно, все разделы, PNG-снимки, smoke.log. С <c>--with-scan</c> выполняется короткая настоящая
/// проверка (только чтение), а действия, меняющие систему, вызываются с автоматическим ответом «Нет» — проверяется, что без
/// подтверждения ничего не происходит. История и журнал пишутся во временную папку, а не в настоящие.
/// </summary>
internal static class SmokeTest
{
    public static async Task<int> RunAsync(string outDir, bool withScan, bool demo = false)
    {
        var log = new List<string>();
        var temp = Directory.CreateTempSubdirectory("nexora-smoke-");
        try
        {
            Directory.CreateDirectory(outDir);
            using (var identity = WindowsIdentity.GetCurrent())
                log.Add($"{Product.Name} {Product.Version}; OS {Environment.OSVersion.Version}; elevated={new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator)}");

            var dialogs = new DeclineAllDialogs();
            var journal = new ActionJournal(Path.Combine(temp.FullName, "actions.jsonl"));
            var vm = new MainViewModel(dialogs, new ReportStore(Path.Combine(temp.FullName, "reports")),
                new ResolutionStore(Path.Combine(temp.FullName, "res.json")), journal);
            var window = new MainWindow
            {
                DataContext = vm, Width = 1180, Height = 900, WindowStartupLocation = WindowStartupLocation.Manual,
                Left = -20000, Top = -20000, ShowActivated = false, ShowInTaskbar = false,
            };
            window.Show();

            if (demo)
            {
                vm.ShowDemo(DemoData.Build());
                log.Add($"demo: {vm.Summary}");
            }
            else if (withScan)
            {
                await vm.ScanAsync(new ScanOptions(TimeSpan.FromSeconds(4)) { IncludeDrivers = false });
                log.Add($"scan: {vm.ProgressText}");
                log.Add($"summary: {vm.Summary}");
                if (!vm.HasReport) throw new InvalidOperationException("после проверки нет отчёта");

                // Действия без подтверждения не выполняются.
                var temp0 = vm.Categories.FirstOrDefault(c => c.Preview.Category == CleanupCategory.UserTemp);
                if (temp0 is { CanCleanFiles: true })
                {
                    vm.CleanCommand.Execute(temp0);
                    await Idle(window);
                    log.Add($"clean declined: asked={dialogs.Asked.LastOrDefault()}, files before={temp0.Preview.FileCount}");
                }
                vm.ExportHtmlCommand.Execute(null);
                log.Add($"export declined: asked={dialogs.Asked.LastOrDefault()}");
                if (File.Exists(journal.File)) throw new InvalidOperationException("в журнале появились действия без подтверждения");
                log.Add("journal: пуст (ни одно действие не выполнено без подтверждения)");
                log.Add($"history entries: {vm.History.Count}");
            }

            foreach (var section in vm.Sections)
            {
                vm.Selected = section;
                await Idle(window);
                var file = Path.Combine(outDir, $"{(int)section.Section:00}-{section.Section}.png");
                Save(window, file);
                log.Add($"OK {section.Title}: находок {section.Findings.Count} -> {Path.GetFileName(file)}");
            }

            // Раскрытая карточка находки — проверка шаблона «что/почему/источник/ограничения».
            vm.Selected = vm.Sections.First(s => s.Section == Section.Security);
            await Idle(window);
            if (FindVisual<Expander>(window) is { } exp)
            {
                exp.IsExpanded = true;
                await Idle(window);
                Save(window, Path.Combine(outDir, "10-Security-expanded.png"));
                log.Add("OK раскрытая карточка -> 10-Security-expanded.png");
            }

            window.Close();
            log.Add("SMOKE PASS");
            return 0;
        }
        catch (Exception ex)
        {
            log.Add($"SMOKE FAIL: {ex}");
            return 1;
        }
        finally
        {
            File.WriteAllLines(Path.Combine(outDir, "smoke.log"), log);
            try { temp.Delete(true); } catch (IOException) { }
        }
    }

    private static async Task Idle(Window w)
    {
        await w.Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
        await Task.Delay(100);
        await w.Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
    }

    private static T? FindVisual<T>(DependencyObject root) where T : DependencyObject
    {
        for (var i = 0; i < VisualTreeHelper.GetChildrenCount(root); i++)
        {
            var c = VisualTreeHelper.GetChild(root, i);
            if (c is T t) return t;
            if (FindVisual<T>(c) is { } found) return found;
        }
        return null;
    }

    private static void Save(Window window, string file)
    {
        var root = (FrameworkElement)window.Content;
        var dpi = VisualTreeHelper.GetDpi(window);
        var bmp = new RenderTargetBitmap(
            (int)(root.ActualWidth * dpi.DpiScaleX), (int)(root.ActualHeight * dpi.DpiScaleY),
            dpi.PixelsPerInchX, dpi.PixelsPerInchY, PixelFormats.Pbgra32);
        bmp.Render(root);
        var enc = new PngBitmapEncoder();
        enc.Frames.Add(BitmapFrame.Create(bmp));
        using var fs = File.Create(file);
        enc.Save(fs);
    }
}
