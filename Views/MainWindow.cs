using System.Text.Json;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using pxdNetworkScanner.Core;

namespace pxdNetworkScanner.Views;

/// <summary>
/// The whole app: a sidebar of device groups (all, computers, printers, phones, media, network gear, smart home,
/// unknown) with an "online only" switch, the device list with search, and the selected device's details.
/// Built in code, pxd neon theme.
/// </summary>
public sealed partial class MainWindow : Window
{
    internal static IBrush Brush(string c) => new SolidColorBrush(Color.Parse(c));
    internal static readonly IBrush Muted = Brush("#8A92A6");
    internal static readonly IBrush Good = Brush("#19F58C");
    internal static readonly IBrush TextB = Brush("#E8EAF0");
    internal static readonly FontFamily Glyphs = new("Segoe Fluent Icons, Segoe MDL2 Assets");
    internal static readonly FontFamily Mono = new("Cascadia Mono, Consolas, monospace");

    private readonly DeviceStore _store;
    private readonly Settings _settings;
    private readonly List<ScanRange> _ranges = ScanRange.Local();
    private readonly Dictionary<int, Button> _nav = [];
    private readonly Dictionary<int, TextBlock> _navCounts = [];
    private readonly Border _notice = new() { Classes = { "notice" }, IsVisible = false, Margin = new Thickness(0, 0, 0, 12) };
    private readonly TextBlock _noticeText = new() { TextWrapping = TextWrapping.Wrap, VerticalAlignment = VerticalAlignment.Center };
    private readonly TextBlock _status = new() { Classes = { "muted" }, VerticalAlignment = VerticalAlignment.Center, TextTrimming = TextTrimming.CharacterEllipsis };
    private readonly ProgressBar _progress = new() { Width = 200, Minimum = 0, Maximum = 1, IsVisible = false, VerticalAlignment = VerticalAlignment.Center };
    private readonly TextBlock _title = new() { FontSize = 22, FontWeight = FontWeight.Bold };
    private readonly TextBlock _subtitle = new() { Classes = { "muted" }, FontSize = 12, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 2, 0, 0) };
    private readonly ComboBox _network = new() { MinWidth = 260, MaxWidth = 340, VerticalAlignment = VerticalAlignment.Center };
    private readonly TextBox _custom = new() { Width = 200, PlaceholderText = "192.168.1.0/24", IsVisible = false, VerticalAlignment = VerticalAlignment.Center };
    private readonly Button _scan = new() { Content = "Scan", Classes = { "primary" }, MinWidth = 96 };
    private readonly ToggleSwitch _onlineOnly = new() { OnContent = "Online only", OffContent = "Online only", Margin = new Thickness(4, 0, 0, 0) };
    private CancellationTokenSource? _cts;
    private int _group;
    private bool _dirty;
    private DateTime _scannedAt;
    private TimeSpan _scanTook;
    private string _scannedRange = "";

    public bool SelfTestMode { get; set; }
    public DeviceStore Store => _store;
    public static readonly string[] GroupNames = Classifier.Groups.Select(g => g.Name).ToArray();

    public MainWindow() : this(new DeviceStore(Path.Combine(Program.DataFolder, "devices.json")), showStart: true)
    {
    }

    public MainWindow(DeviceStore store, bool showStart)
    {
        _store = store;
        _settings = Settings.Load();
        Title = "pxd Network Scanner";
        Icon = BrandIcon.Window();
        Width = 1240;
        Height = 820;
        MinWidth = 980;
        MinHeight = 620;
        WindowStartupLocation = WindowStartupLocation.CenterScreen;

        var body = new Grid { ColumnDefinitions = new ColumnDefinitions("230,*") };
        body.Children.Add(BuildSidebar());
        var main = new Grid { RowDefinitions = new RowDefinitions("Auto,Auto,Auto,*,Auto"), Margin = new Thickness(22, 16, 22, 10) };
        Grid.SetColumn(main, 1);
        body.Children.Add(main);

        main.Children.Add(BuildHeader());
        var ng = new Grid { ColumnDefinitions = new ColumnDefinitions("*,Auto") };
        ng.Children.Add(_noticeText);
        var dismiss = new Button { Content = "Dismiss", Classes = { "ghost" }, MinHeight = 28, Padding = new Thickness(10, 2), Margin = new Thickness(8, 0, 0, 0) };
        dismiss.Click += (_, _) => _notice.IsVisible = false;
        Grid.SetColumn(dismiss, 1);
        ng.Children.Add(dismiss);
        _notice.Child = ng;
        Grid.SetRow(_notice, 1);
        main.Children.Add(_notice);
        var tools = BuildToolbar();
        Grid.SetRow(tools, 2);
        main.Children.Add(tools);
        var list = BuildDeviceArea();
        Grid.SetRow(list, 3);
        main.Children.Add(list);
        var bar = new Grid { ColumnDefinitions = new ColumnDefinitions("*,Auto"), Margin = new Thickness(0, 10, 0, 0) };
        bar.Children.Add(_status);
        Grid.SetColumn(_progress, 1);
        bar.Children.Add(_progress);
        Grid.SetRow(bar, 4);
        main.Children.Add(bar);

        Content = pxdStandard.pxdChrome.Wrap(this, body, Title, BrandIcon.Render(36));
        _onlineOnly.IsChecked = _settings.OnlineOnly;
        _onlineOnly.IsCheckedChanged += (_, _) =>
        {
            _settings.OnlineOnly = _onlineOnly.IsChecked == true;
            _settings.Save();
            Refresh();
        };
        FillNetworks();
        ShowGroup(0);
        _status.Text = _ranges.Count == 0 ? "No network connection found. Type a range to scan." : "Ready.";

        var timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(350) };
        timer.Tick += (_, _) =>
        {
            if (!_dirty) return;
            _dirty = false;
            Refresh();
        };
        timer.Start();
        Closed += (_, _) =>
        {
            timer.Stop();
            _cts?.Cancel();
        };
        KeyDown += (_, e) =>
        {
            if (e.Key == Key.F5) _ = ScanAsync();
            else if (e.Key == Key.F && e.KeyModifiers.HasFlag(KeyModifiers.Control)) _search.Focus();
        };
        // Opens on the start choices (this PC's network, or another one) rather than scanning straight away.
        if (!showStart) _start.IsVisible = false;
        Refresh();
    }

    // ---------- Shell ----------

    private Control BuildSidebar()
    {
        var dock = new DockPanel { Background = Brush("#0B0E13") };
        var head = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 10, Margin = new Thickness(16, 16, 16, 18) };
        head.Children.Add(new Image { Source = BrandIcon.Render(72), Width = 36, Height = 36 });
        var names = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
        names.Children.Add(new TextBlock { Text = "pxd NETWORK", FontSize = 13, FontWeight = FontWeight.Bold, LetterSpacing = 1.4, Classes = { "neon" } });
        names.Children.Add(new TextBlock { Text = "SCANNER", FontSize = 13, FontWeight = FontWeight.Bold, LetterSpacing = 1.4, Classes = { "neon" } });
        head.Children.Add(names);
        DockPanel.SetDock(head, Dock.Top);
        dock.Children.Add(head);

        var foot = new StackPanel { Spacing = 8, Margin = new Thickness(12, 8, 12, 14) };
        ToolTip.SetTip(_onlineOnly, "Hide devices that were seen before but didn't answer this scan.");
        foot.Children.Add(_onlineOnly);
        var forget = new Button { Content = "Forget offline devices", HorizontalAlignment = HorizontalAlignment.Stretch };
        ToolTip.SetTip(forget, "Removes every device that didn't answer the latest scan from the list (names you gave them too).");
        forget.Click += (_, _) =>
        {
            var n = _store.Items.Count(d => !d.Online);
            _store.ForgetOffline();
            _store.Save();
            Refresh();
            ShowNotice(n == 0 ? "There were no offline devices." : $"Forgot {n} offline device{(n == 1 ? "" : "s")}.", good: true);
        };
        foot.Children.Add(forget);
        foot.Children.Add(new TextBlock { Text = $"Version {typeof(MainWindow).Assembly.GetName().Version?.ToString(3)}", Classes = { "muted" }, FontSize = 11, Margin = new Thickness(4, 2, 0, 0) });
        DockPanel.SetDock(foot, Dock.Bottom);
        dock.Children.Add(foot);

        var nav = new StackPanel { Spacing = 2, Margin = new Thickness(10, 0) };
        nav.Children.Add(new TextBlock { Text = "SHOW", Classes = { "label" }, Margin = new Thickness(12, 0, 0, 6) });
        for (var i = 0; i < Classifier.Groups.Length; i++)
        {
            var index = i;
            var g = Classifier.Groups[i];
            var row = new Grid { ColumnDefinitions = new ColumnDefinitions("26,*,Auto") };
            row.Children.Add(new TextBlock { Text = g.Glyph, FontFamily = Glyphs, FontSize = 15, VerticalAlignment = VerticalAlignment.Center });
            var label = new TextBlock { Text = g.Name, FontSize = 13.5, FontWeight = FontWeight.SemiBold, VerticalAlignment = VerticalAlignment.Center, TextTrimming = TextTrimming.CharacterEllipsis };
            Grid.SetColumn(label, 1);
            row.Children.Add(label);
            var count = new TextBlock { Classes = { "muted" }, FontSize = 12, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(6, 0, 0, 0) };
            Grid.SetColumn(count, 2);
            row.Children.Add(count);
            _navCounts[i] = count;
            var b = new Button
            {
                Content = row, Classes = { "ghost" }, HorizontalAlignment = HorizontalAlignment.Stretch,
                HorizontalContentAlignment = HorizontalAlignment.Stretch, Padding = new Thickness(12, 8), MinHeight = 40,
            };
            b.Click += (_, _) => ShowGroup(index);
            _nav[i] = b;
            nav.Children.Add(b);
        }

        dock.Children.Add(new ScrollViewer { Content = nav });
        return dock;
    }

    private Control BuildHeader()
    {
        var g = new Grid { ColumnDefinitions = new ColumnDefinitions("*,Auto"), Margin = new Thickness(0, 0, 0, 12) };
        var left = new StackPanel();
        left.Children.Add(_title);
        left.Children.Add(_subtitle);
        g.Children.Add(left);
        var r = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8, VerticalAlignment = VerticalAlignment.Bottom };
        ToolTip.SetTip(_network, "The network to scan. Networks bigger than a /24 are scanned as the /24 around this PC; type a custom range for more.");
        r.Children.Add(_network);
        r.Children.Add(_custom);
        ToolTip.SetTip(_scan, "Scan the network (F5).");
        _scan.Click += async (_, _) => await ScanAsync();
        r.Children.Add(_scan);
        var export = new Button { Content = "Export…" };
        ToolTip.SetTip(export, "Save the devices shown as a web page, CSV (Excel), JSON or text.");
        export.Click += async (_, _) => await ExportAsync();
        r.Children.Add(export);
        Grid.SetColumn(r, 1);
        g.Children.Add(r);
        return g;
    }

    private void FillNetworks()
    {
        _network.Items.Clear();
        foreach (var r in _ranges) _network.Items.Add(r.Label);
        _network.Items.Add("Custom range…");
        var saved = _settings.CustomRange.Length > 0 && _settings.UseCustom;
        _custom.Text = _settings.CustomRange;
        _network.SelectedIndex = saved || _ranges.Count == 0 ? _ranges.Count : 0;
        _custom.IsVisible = _network.SelectedIndex == _ranges.Count;
        _network.SelectionChanged += (_, _) =>
        {
            _custom.IsVisible = _network.SelectedIndex == _ranges.Count;
            _settings.UseCustom = _custom.IsVisible;
            _settings.Save();
            if (_custom.IsVisible) _custom.Focus();
        };
        _custom.KeyDown += async (_, e) =>
        {
            if (e.Key == Key.Enter) await ScanAsync();
        };
    }

    /// <summary>The range picked in the box, or the typed custom one (null with a notice when it doesn't read).</summary>
    private ScanRange? CurrentRange()
    {
        var i = _network.SelectedIndex;
        if (i >= 0 && i < _ranges.Count) return _ranges[i];
        var range = ScanRange.Parse(_custom.Text ?? "", out var error);
        if (range is null)
        {
            ShowNotice(error);
            return null;
        }

        _settings.CustomRange = (_custom.Text ?? "").Trim();
        _settings.Save();
        // Borrow this PC's address, gateway and broadcast from the adapter on that network, if there is one.
        var local = _ranges.FirstOrDefault(l => l.LocalIp is not null && range.Contains(l.LocalIp)) ?? _ranges.FirstOrDefault(l => range.First >= l.First - 1 && range.Last <= l.Last + 1);
        return local is null ? range : range with { LocalIp = local.LocalIp, LocalMac = local.LocalMac, Gateway = local.Gateway, Broadcast = local.Broadcast };
    }

    public void ShowGroup(int index)
    {
        _group = index;
        foreach (var (n, b) in _nav)
        {
            b.Background = n == index ? Brush("#142027") : Brushes.Transparent;
            b.Foreground = n == index ? Good : TextB;
        }

        Refresh();
    }

    public void ShowNotice(string text, bool good = false)
    {
        _notice.Background = Brush(good ? "#0C2A1D" : "#2A2210");
        _notice.BorderBrush = Brush(good ? "#146B44" : "#7A5A1A");
        _noticeText.Foreground = Brush(good ? "#7DF5BC" : "#F5C97A");
        _noticeText.Text = text;
        _notice.IsVisible = true;
    }

    // ---------- Scanning ----------

    public bool Scanning => _cts is not null;

    public async Task ScanAsync()
    {
        if (_cts is not null)
        {
            _cts.Cancel();
            return;
        }

        var range = CurrentRange();
        if (range is null) return;
        _start.IsVisible = false;
        _notice.IsVisible = false;
        _cts = new CancellationTokenSource();
        _scan.Content = "Stop";
        _scan.Classes.Remove("primary");
        _progress.Value = 0;
        _progress.IsVisible = true;
        _status.Text = $"Scanning {range.Text}…";
        BeforeScan(range);
        var started = DateTime.Now.AddSeconds(-1);
        _store.BeginScan(range);
        _scannedRange = range.Text;
        Refresh();
        var progress = new Progress<ScanProgress>(p =>
        {
            if (_cts is null) return;
            var share = p.Total == 0 ? 0 : (double)p.Done / p.Total;
            _progress.Value = p.Phase == "Pinging" ? share * 0.45 : p.Phase == "Done" ? 1 : 0.45 + share * 0.5;
            _status.Text = p.Phase == "Pinging" ? $"Pinging {range.Text}: {p.Done} of {p.Total}…" : p.Phase == "Done" ? "Finishing…" : $"Identifying devices: {p.Done} of {p.Total}…";
        });
        void Update(Device d) => Dispatcher.UIThread.Post(() =>
        {
            _store.Merge(d);
            _dirty = true;
        });

        try
        {
            var cts = _cts;
            var result = await Task.Run(() => Scanner.RunAsync(range, new ScanOptions(), progress, Update, cts.Token));
            await Dispatcher.UIThread.InvokeAsync(() => { }, DispatcherPriority.Background);   // let queued updates land first
            foreach (var d in result.Devices) _store.Merge(d);
            AfterScan(started);
            _store.Save();
            _scannedAt = DateTime.Now;
            _scanTook = result.Elapsed;
            var online = result.Devices.Count;
            _status.Text = result.Cancelled
                ? $"Stopped after {result.Elapsed.TotalSeconds:0.0} s; {online} device{(online == 1 ? "" : "s")} found so far."
                : $"Scanned {range.Count:N0} addresses in {result.Elapsed.TotalSeconds:0.0} s: {online} device{(online == 1 ? "" : "s")} answered. F5 scans again.";
        }
        catch (Exception ex)
        {
            ShowNotice("The scan stopped: " + ex.Message);
            _status.Text = "Ready.";
        }
        finally
        {
            _cts?.Dispose();
            _cts = null;
            _scan.Content = "Scan";
            if (!_scan.Classes.Contains("primary")) _scan.Classes.Add("primary");
            _progress.IsVisible = false;
            Refresh();
        }
    }

    /// <summary>Shows given devices as if a scan had found them (self-test and README screenshots).</summary>
    public void SetDevices(IEnumerable<Device> devices, string range, TimeSpan took, bool sample = false)
    {
        _start.IsVisible = false;
        if (sample)
        {
            // Screenshots show the made-up network in the picker too, never this PC's real one.
            _network.Items.Clear();
            _network.Items.Add("Ethernet  ·  " + range);
            _network.Items.Add("Custom range…");
            _network.SelectedIndex = 0;
        }

        foreach (var d in devices)
        {
            var kept = _store.Merge(d);
            kept.Online = d.Online;
            kept.LastSeen = d.LastSeen;
            if (d.Label.Length > 0) kept.Label = d.Label;
        }

        _scannedRange = range;
        _scannedAt = DateTime.Now;
        _scanTook = took;
        _status.Text = $"Scanned {range} in {took.TotalSeconds:0.0} s: {_store.Items.Count(x => x.Online)} devices answered. F5 scans again.";
        Refresh();
    }

    // ---------- Export ----------

    private async Task ExportAsync()
    {
        var shown = Visible().ToList();
        if (shown.Count == 0)
        {
            ShowNotice("There's nothing to export yet: scan first, or change the filter.");
            return;
        }

        try
        {
            var file = await StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
            {
                Title = "Export devices",
                SuggestedFileName = $"network-{DateTime.Now:yyyyMMdd-HHmm}.html",
                FileTypeChoices =
                [
                    new FilePickerFileType("Web page") { Patterns = ["*.html"] }, new FilePickerFileType("CSV (Excel)") { Patterns = ["*.csv"] },
                    new FilePickerFileType("JSON") { Patterns = ["*.json"] }, new FilePickerFileType("Text") { Patterns = ["*.txt"] },
                ],
            });
            if (file?.TryGetLocalPath() is not { } path) return;
            await File.WriteAllTextAsync(path, Report.For(path, shown, _scannedRange.Length > 0 ? _scannedRange : "network", _scannedAt == default ? DateTime.Now : _scannedAt));
            ShowNotice($"{shown.Count} device{(shown.Count == 1 ? "" : "s")} saved to {path}", good: true);
        }
        catch (Exception ex)
        {
            ShowNotice("Couldn't save the file: " + ex.Message);
        }
    }

    // ---------- Settings ----------

    private sealed class Settings
    {
        public bool OnlineOnly { get; set; }
        public bool UseCustom { get; set; }
        public string CustomRange { get; set; } = "";

        private static string File => Path.Combine(Program.DataFolder, "settings.json");

        public static Settings Load()
        {
            try
            {
                return System.IO.File.Exists(File) ? JsonSerializer.Deserialize<Settings>(System.IO.File.ReadAllText(File)) ?? new() : new();
            }
            catch
            {
                return new();
            }
        }

        public void Save()
        {
            try
            {
                Directory.CreateDirectory(Program.DataFolder);
                System.IO.File.WriteAllText(File, JsonSerializer.Serialize(this));
            }
            catch
            {
            }
        }
    }

    internal static Border Pill(string text, string kind) => new() { Classes = { "pill", kind }, Child = new TextBlock { Text = text } };
}
