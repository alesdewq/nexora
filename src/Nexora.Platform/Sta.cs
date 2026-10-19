namespace Nexora.Platform;

/// <summary>Выполнить код на отдельном STA-потоке (нужно для COM-объектов оболочки Windows).</summary>
internal static class Sta
{
    public static T Run<T>(Func<T> f)
    {
        T result = default!;
        Exception? error = null;
        var t = new Thread(() => { try { result = f(); } catch (Exception ex) { error = ex; } }) { IsBackground = true };
        t.SetApartmentState(ApartmentState.STA);
        t.Start();
        t.Join();
        if (error is not null) System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(error).Throw();
        return result;
    }
}
