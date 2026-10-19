using Nexora.Cleanup;
using Nexora.Platform.Actions;

namespace Nexora.Platform.Tests;

/// <summary>Действия этапа 8 проверяются ТОЛЬКО на специально созданных временных файлах; реальные данные не затрагиваются.</summary>
public class ActionsTests
{
    [Fact]
    public void Remover_PermanentDelete_OnTestFile()
    {
        var dir = Directory.CreateTempSubdirectory("nexora-remove-");
        try
        {
            var f = Path.Combine(dir.FullName, "victim.tmp");
            File.WriteAllText(f, "test");
            new WindowsFileRemover().Remove(f, toRecycleBin: false);
            Assert.False(File.Exists(f));
        }
        finally { dir.Delete(true); }
    }

    [Fact]
    public void RecycleBinQuery_Works()
    {
        var p = CleanupCollector.RecycleBin();
        Assert.Null(p.Unavailable);
        Assert.True(p.TotalBytes >= 0);
    }

    [Fact]
    public void StartupActions_RefuseMachineWideEntries()
    {
        var machine = new Nexora.SecurityAudit.AutorunEntry(Nexora.SecurityAudit.AutorunLocation.RunKey, "HKLM", "x", "x.exe", null, null,
            Nexora.SecurityAudit.SignatureState.NotChecked, null, true, MachineWide: true);
        Assert.False(StartupActions.CanToggle(machine));
        var journal = new ActionJournal(Path.Combine(Path.GetTempPath(), $"nexora-j-{Guid.NewGuid():N}.jsonl"));
        Assert.Throws<InvalidOperationException>(() => StartupActions.SetEnabled(machine, false, journal));
        Assert.False(File.Exists(journal.File));
    }
}
