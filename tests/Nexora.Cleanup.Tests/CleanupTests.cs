namespace Nexora.Cleanup.Tests;

public class CleanupTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.UtcNow;

    [Fact]
    public void Preview_SkipsRecentFiles()
    {
        using var t = new TempTree();
        t.File("old.tmp", 1000);
        t.File("sub/old2.tmp", 2000);
        t.File("fresh.tmp", 500, TimeSpan.FromHours(1));
        var p = PreviewScanner.ScanTemp(CleanupCategory.UserTemp, t.Root, Now, TestContext.Current.CancellationToken);
        Assert.Equal(2, p.FileCount);
        Assert.Equal(3000, p.TotalBytes);
        Assert.True(p.CanClean);
        Assert.DoesNotContain(p.Items, i => i.Path.EndsWith("fresh.tmp", StringComparison.Ordinal));
    }

    [Fact]
    public void Preview_DoesNotFollowJunctions()
    {
        using var outside = new TempTree();
        var precious = outside.File("precious.docx", 4096);
        using var t = new TempTree();
        t.File("a.tmp");
        TempTree.Junction(Path.Combine(t.Root, "link"), outside.Root);

        var p = PreviewScanner.ScanTemp(CleanupCategory.UserTemp, t.Root, Now, TestContext.Current.CancellationToken);
        Assert.Single(p.Items);
        Assert.DoesNotContain(p.Items, i => i.Path.Contains("precious", StringComparison.Ordinal));
        Assert.True(File.Exists(precious));
    }

    [Fact]
    public void Preview_MissingFolder_IsUnavailable()
    {
        var p = PreviewScanner.ScanTemp(CleanupCategory.UserTemp, @"C:\definitely\missing\nexora", Now, TestContext.Current.CancellationToken);
        Assert.NotNull(p.Unavailable);
        Assert.False(p.CanClean);
    }

    [Fact]
    public void LargeFiles_AreNeverCleanable()
    {
        using var t = new TempTree();
        var p = PreviewScanner.ScanLargeFiles(t.Root, TestContext.Current.CancellationToken);
        Assert.False(p.CanClean);
        Assert.Throws<InvalidOperationException>(() => CleanupPlan.Confirm(p, [], true, Now));
    }

    [Fact]
    public void Guard_AcceptsUnchangedFileInsideRoot()
    {
        using var t = new TempTree();
        var f = t.File("x/y.tmp");
        var fi = new FileInfo(f);
        Assert.Null(PathGuard.Validate(f, t.Root, fi.Length, fi.LastWriteTimeUtc));
    }

    [Theory]
    [InlineData(@"..\escape.txt", "«..»")]
    [InlineData(@"\\server\share\x.tmp", "сетевые")]
    [InlineData(@"file.tmp:stream", "потоки")]
    [InlineData("file.tmp.", "точкой")]
    public void Guard_RejectsTrickyPaths(string relative, string expected)
    {
        using var t = new TempTree();
        var candidate = relative.StartsWith(@"\\", StringComparison.Ordinal) ? relative : t.Root + "\\" + relative;
        Assert.Contains(expected, PathGuard.Validate(candidate, t.Root, 0, Now));
    }

    [Fact]
    public void Guard_RejectsFileOutsideRoot_EvenWithSharedPrefix()
    {
        using var t = new TempTree();
        var sibling = t.Root + "-evil";
        Directory.CreateDirectory(sibling);
        try
        {
            var f = Path.Combine(sibling, "x.tmp");
            File.WriteAllText(f, "x");
            var fi = new FileInfo(f);
            Assert.Contains("вне разрешённой папки", PathGuard.Validate(f, t.Root, fi.Length, fi.LastWriteTimeUtc));
        }
        finally { Directory.Delete(sibling, true); }
    }

    [Fact]
    public void Guard_RejectsPathThroughJunction()
    {
        using var outside = new TempTree();
        var precious = outside.File("precious.docx");
        using var t = new TempTree();
        TempTree.Junction(Path.Combine(t.Root, "link"), outside.Root);
        var viaLink = Path.Combine(t.Root, "link", "precious.docx");
        var fi = new FileInfo(precious);
        Assert.Contains("ссылка", PathGuard.Validate(viaLink, t.Root, fi.Length, fi.LastWriteTimeUtc));
    }

    [Fact]
    public void Guard_RejectsChangedOrMissingFile()
    {
        using var t = new TempTree();
        var f = t.File("a.tmp", 10);
        var fi = new FileInfo(f);
        var (len, time) = (fi.Length, fi.LastWriteTimeUtc);
        File.WriteAllBytes(f, new byte[20]);
        Assert.Contains("изменился", PathGuard.Validate(f, t.Root, len, time));
        File.Delete(f);
        Assert.Contains("не существует", PathGuard.Validate(f, t.Root, len, time));
    }

    [Fact]
    public void Plan_RejectsItemsNotFromPreview()
    {
        using var t = new TempTree();
        t.File("a.tmp");
        var p = PreviewScanner.ScanTemp(CleanupCategory.UserTemp, t.Root, Now, TestContext.Current.CancellationToken);
        var forged = new CleanupCandidate(@"C:\Windows\System32\kernel32.dll", 1, Now);
        Assert.Throws<InvalidOperationException>(() => CleanupPlan.Confirm(p, [forged], true, Now));
    }

    [Fact]
    public void Execute_RemovesOnlyValidated_AndJournals()
    {
        using var t = new TempTree();
        t.File("a.tmp", 10);
        t.File("b.tmp", 20);
        var p = PreviewScanner.ScanTemp(CleanupCategory.UserTemp, t.Root, Now, TestContext.Current.CancellationToken);
        var changed = p.Items.Single(i => i.Path.EndsWith("b.tmp", StringComparison.Ordinal));
        File.WriteAllBytes(changed.Path, new byte[99]); // изменён после предпросмотра — должен быть пропущен

        var plan = CleanupPlan.Confirm(p, p.Items, toRecycleBin: false, Now);
        var journal = new ActionJournal(Path.Combine(t.Root, "..", Path.GetFileName(t.Root) + "-journal.jsonl"));
        try
        {
            var remover = new RecordingRemover();
            var report = SafeCleaner.Execute(plan, remover, journal, () => Now, ct: TestContext.Current.CancellationToken);
            Assert.Equal(1, report.Removed);
            Assert.Equal(1, report.Skipped);
            Assert.True(File.Exists(changed.Path));
            Assert.Single(remover.Removed);
            var entries = journal.Read();
            Assert.Equal("cleanup.start", entries[0].Action);
            Assert.Equal("cleanup.end", entries[^1].Action);
            Assert.Equal(4, entries.Count);
        }
        finally { File.Delete(journal.File); }
    }

    [Fact]
    public void Execute_LockedFile_IsSkippedNotCrash()
    {
        using var t = new TempTree();
        var f = t.File("locked.tmp", 10);
        var p = PreviewScanner.ScanTemp(CleanupCategory.UserTemp, t.Root, Now, TestContext.Current.CancellationToken);
        var journal = new ActionJournal(Path.Combine(Path.GetTempPath(), $"nexora-j-{Guid.NewGuid():N}.jsonl"));
        try
        {
            using (File.Open(f, FileMode.Open, FileAccess.Read, FileShare.None))
            {
                var report = SafeCleaner.Execute(CleanupPlan.Confirm(p, p.Items, false, Now), new RecordingRemover(), journal, () => Now, ct: TestContext.Current.CancellationToken);
                Assert.Equal(0, report.Removed);
                Assert.Equal(1, report.Skipped);
            }
        }
        finally { File.Delete(journal.File); }
    }

    [Theory]
    [InlineData(@"MsiExec.exe /I{12345678-1234-1234-1234-123456789ABC}", @"C:\Windows\System32\msiexec.exe", "/X{12345678-1234-1234-1234-123456789ABC}", true)]
    [InlineData(@"""C:\Program Files\App\unins000.exe"" /SILENT", @"C:\Program Files\App\unins000.exe", "/SILENT", false)]
    [InlineData(@"C:\Program Files\App\uninstall.exe", @"C:\Program Files\App\uninstall.exe", "", false)]
    public void Uninstall_Parse(string raw, string exe, string args, bool msi)
    {
        var p = UninstallCommand.Parse(raw, @"C:\Windows\System32")!;
        Assert.Equal(exe, p.FileName);
        Assert.Equal(args, p.Arguments);
        Assert.Equal(msi, p.IsMsi);
    }

    [Theory]
    [InlineData(@"cmd.exe /c del C:\*")]
    [InlineData(@"""C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"" -c x")]
    [InlineData("uninstall.exe")]
    [InlineData(@"C:\..\x\uninstall.exe")]
    [InlineData("")]
    public void Uninstall_RejectsWrappersAndRelativePaths(string raw) => Assert.Null(UninstallCommand.Parse(raw, @"C:\Windows\System32"));

    [Fact]
    public void Analyzer_BigTempIsInfoWithAutomatedAction()
    {
        var cat = new CategoryPreview(CleanupCategory.UserTemp, "Временные файлы пользователя", "x", @"C:\t", 10, 2L << 30, [], true, "c");
        var r = Assert.Single(CleanupAnalyzer.Analyze(new CleanupPreview(Now, [cat])));
        Assert.Equal(Severity.Info, r.Severity);
        Assert.True(r.AutomatedActionAvailable);
    }
}
