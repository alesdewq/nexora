using System.IO;
using System.Security.Principal;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using Nexora.App.ViewModels;
using Nexora.Core;

namespace Nexora.App;

/// <summary>
/// Неинтерактивная проверка: открыть окно, пройти все разделы, сохранить снимки в PNG. Работает и в сессии без рабочего стола
/// (окно рисуется в RenderTargetBitmap). Ничего в системе не меняет.
/// </summary>
internal static class SmokeTest
{
    public static async Task<int> RunAsync(Window window, MainViewModel vm, string outDir)
    {
        var log = new List<string>();
        try
        {
            Directory.CreateDirectory(outDir);
            using var identity = WindowsIdentity.GetCurrent();
            var elevated = new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
            log.Add($"{Product.Name} {Product.Version}; OS {Environment.OSVersion.Version}; elevated={elevated}");

            window.Width = 1180; window.Height = 760;
            window.WindowStartupLocation = WindowStartupLocation.Manual;
            window.Left = -20000; window.Top = -20000; window.ShowActivated = false; window.ShowInTaskbar = false;
            window.Show();

            foreach (var section in vm.Sections)
            {
                vm.Selected = section;
                await window.Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
                var file = Path.Combine(outDir, $"{(int)section.Section:00}-{section.Section}.png");
                Save(window, file);
                log.Add($"OK {section.Title} -> {Path.GetFileName(file)}");
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
        }
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
