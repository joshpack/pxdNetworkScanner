using Avalonia;
using Avalonia.Headless;
using Avalonia.Threading;
using pxdNetworkScanner.Core;

namespace pxdNetworkScanner;

internal static class Program
{
    public const string AppId = "pxdNetworkScanner";

    /// <summary>%APPDATA%\pxdNetworkScanner (window placement, remembered devices), or PXDNS_DATA (tests).</summary>
    public static string DataFolder =>
        Environment.GetEnvironmentVariable("PXDNS_DATA") is { Length: > 0 } custom
            ? custom
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), AppId);

    private static bool Has(string[] args, string flag) => args.Any(a => a.Equals(flag, StringComparison.OrdinalIgnoreCase));

    private static string? After(string[] args, string flag)
    {
        var i = Array.FindIndex(args, a => a.Equals(flag, StringComparison.OrdinalIgnoreCase));
        return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
    }

    [STAThread]
    public static int Main(string[] args)
    {
        if (After(args, "--write-icon") is { } icon)
        {
            BuildAvaloniaApp().SetupWithoutStarting();
            BrandIcon.Write(icon);
            return 0;
        }

        if (After(args, "--self-test") is { } testDir)
        {
            SelfTest.Dir = Path.GetFullPath(testDir);
            SelfTest.Sample = Has(args, "--sample");
            SelfTest.Live = !Has(args, "--no-scan");
            Directory.CreateDirectory(SelfTest.Dir);
            if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable("PXDNS_DATA")))
                Environment.SetEnvironmentVariable("PXDNS_DATA", Path.Combine(SelfTest.Dir, "data"));
            pxdStandard.pxdChrome.Configure(AppId, DataFolder);
            AppBuilder.Configure<App>()
                .UseSkia()
                .UseHeadless(new AvaloniaHeadlessPlatformOptions { UseHeadlessDrawing = false })
                .SetupWithoutStarting();
            using var done = new CancellationTokenSource();
            Dispatcher.UIThread.Post(async () =>
            {
                await SelfTest.RunAsync();
                done.Cancel();
            });
            Dispatcher.UIThread.MainLoop(done.Token);
            return SelfTest.ExitCode;
        }

        // --report file.html|.csv|.json|.txt [--range 192.168.1.0/24]: one scan, no window, for scripts.
        if (After(args, "--report") is { } report)
        {
            try
            {
                var range = After(args, "--range") is { } r ? ScanRange.Parse(r, out _) : ScanRange.Local().FirstOrDefault();
                if (range is null) return 2;
                var local = ScanRange.Local().FirstOrDefault(l => range.LocalIp is null && l.LocalIp is not null && range.Contains(l.LocalIp));
                if (local is not null) range = range with { LocalIp = local.LocalIp, LocalMac = local.LocalMac, Gateway = local.Gateway, Broadcast = local.Broadcast };
                var result = Scanner.RunAsync(range, new ScanOptions(), null, null, CancellationToken.None).GetAwaiter().GetResult();
                File.WriteAllText(Path.GetFullPath(report), Report.For(report, result.Devices, range.Text, DateTime.Now));
                return 0;
            }
            catch
            {
                return 1;
            }
        }

        if (!SingleInstance.Claim(SingleInstance.Name(AppId), args))
            return 0;

        pxdStandard.pxdChrome.Configure(AppId, DataFolder);
        BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
        return 0;
    }

    public static AppBuilder BuildAvaloniaApp() =>
        AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .With(new Win32PlatformOptions { RenderingMode = new[] { Win32RenderingMode.Software } })
            .LogToTrace();
}
