using System.Diagnostics;
using System.Net;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Shapes;
using Avalonia.Controls.Templates;
using Avalonia.Layout;
using Avalonia.Media;
using pxdNetworkScanner.Core;

namespace pxdNetworkScanner.Views;

public sealed partial class MainWindow
{
    private readonly TextBox _search = new() { PlaceholderText = "Search name, IP, MAC, maker, model or port…", VerticalAlignment = VerticalAlignment.Center };
    private readonly ComboBox _sort = new() { MinWidth = 150, VerticalAlignment = VerticalAlignment.Center };
    private readonly ListBox _list = new() { Classes = { "log" } };
    private readonly Border _details = new() { Classes = { "card" }, Padding = new Thickness(18), Margin = new Thickness(14, 0, 0, 0) };
    private readonly TextBlock _empty = new() { Classes = { "muted" }, TextWrapping = TextWrapping.Wrap, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center, TextAlignment = TextAlignment.Center, Margin = new Thickness(30), MaxWidth = 420 };
    private Device? _selected;
    private bool _refreshing;

    private static readonly string[] Sorts = ["Sort: IP address", "Sort: name", "Sort: type", "Sort: last seen"];

    private Control BuildToolbar()
    {
        var g = new Grid { ColumnDefinitions = new ColumnDefinitions("*,Auto"), Margin = new Thickness(0, 0, 0, 10) };
        _search.TextChanged += (_, _) => Refresh();
        g.Children.Add(_search);
        foreach (var s in Sorts) _sort.Items.Add(s);
        _sort.SelectedIndex = 0;
        _sort.SelectionChanged += (_, _) => Refresh();
        _sort.Margin = new Thickness(8, 0, 0, 0);
        Grid.SetColumn(_sort, 1);
        g.Children.Add(_sort);
        return g;
    }

    private Control BuildDeviceArea()
    {
        var g = new Grid { ColumnDefinitions = new ColumnDefinitions("*,380") };
        _list.ItemTemplate = new FuncDataTemplate<Device>((d, _) => d is null ? new Panel() : Row(d), supportsRecycling: false);
        _list.SelectionChanged += (_, _) =>
        {
            if (_refreshing) return;
            _selected = _list.SelectedItem as Device;
            ShowDetails();
        };
        var host = new Grid();
        host.Children.Add(_list);
        host.Children.Add(_empty);
        g.Children.Add(host);
        Grid.SetColumn(_details, 1);
        g.Children.Add(_details);
        ShowDetails();
        return g;
    }

    /// <summary>The devices the sidebar group, the online switch and the search box let through, in the chosen order.</summary>
    public IEnumerable<Device> Visible() => Sorted(_store.Items.Where(d => InGroup(d, _group) && (_onlineOnly.IsChecked != true || d.Online) && Matches(d, _search.Text ?? "")));

    private static bool InGroup(Device d, int group) => group == 0 || Classifier.Groups[group].Kinds.Contains(d.Kind);

    private static bool Matches(Device d, string q)
    {
        q = q.Trim();
        if (q.Length == 0) return true;
        var mac = q.Replace(":", "").Replace("-", "");
        return d.Name.Contains(q, StringComparison.OrdinalIgnoreCase) || d.Ip.StartsWith(q) || d.KindText.Contains(q, StringComparison.OrdinalIgnoreCase)
               || mac.Length >= 2 && d.Mac.Contains(mac, StringComparison.OrdinalIgnoreCase) || d.Vendor.Contains(q, StringComparison.OrdinalIgnoreCase)
               || d.Model.Contains(q, StringComparison.OrdinalIgnoreCase) || d.Manufacturer.Contains(q, StringComparison.OrdinalIgnoreCase)
               || d.HostNames.Any(h => h.Contains(q, StringComparison.OrdinalIgnoreCase)) || d.Os.Contains(q, StringComparison.OrdinalIgnoreCase)
               || int.TryParse(q, out var port) && d.Ports.Contains(port) || d.HttpTitle.Contains(q, StringComparison.OrdinalIgnoreCase);
    }

    private IEnumerable<Device> Sorted(IEnumerable<Device> items) => _sort.SelectedIndex switch
    {
        1 => items.OrderByDescending(d => d.Online).ThenBy(d => d.Name, StringComparer.OrdinalIgnoreCase),
        2 => items.OrderBy(d => d.Kind).ThenBy(d => d.IpSort),
        3 => items.OrderByDescending(d => d.Online).ThenByDescending(d => d.LastSeen),
        _ => items.OrderBy(d => d.IpSort),
    };

    public void Refresh()
    {
        var pool = _store.Items.Where(d => _onlineOnly.IsChecked != true || d.Online).ToList();
        for (var i = 0; i < Classifier.Groups.Length; i++)
            _navCounts[i].Text = pool.Count(d => InGroup(d, i)).ToString();

        var shown = Visible().ToList();
        _refreshing = true;
        _list.ItemsSource = shown;
        if (_selected is not null && shown.Contains(_selected)) _list.SelectedItem = _selected;
        _refreshing = false;
        if (_selected is not null && !shown.Contains(_selected)) _selected = null;
        ShowDetails();

        var online = _store.Items.Count(d => d.Online);
        var offline = _store.Items.Count - online;
        _title.Text = Classifier.Groups[_group].Name;
        _subtitle.Text = _scannedRange.Length == 0 && _store.Items.Count == 0
            ? "Press Scan to find everything on your network."
            : $"{(_scannedRange.Length > 0 ? _scannedRange + "  ·  " : "")}{online} online{(offline > 0 ? $", {offline} offline" : "")}"
              + (_scannedAt != default ? $"  ·  scanned {_scannedAt:HH:mm} in {_scanTook.TotalSeconds:0.0} s" : Scanning ? "  ·  scanning…" : "")
              + (shown.Count != _store.Items.Count ? $"  ·  showing {shown.Count}" : "");
        _empty.IsVisible = shown.Count == 0;
        _empty.Text = Scanning ? "Looking…"
            : _store.Items.Count == 0 ? "No devices yet. Pick your network at the top and press Scan."
            : (_search.Text ?? "").Trim().Length > 0 ? "Nothing matches that search."
            : _onlineOnly.IsChecked == true ? "None of these are online right now. Turn off \"Online only\" to see the ones seen before."
            : "No devices of this kind were found.";
    }

    // ---------- One row ----------

    private static Control Row(Device d)
    {
        var g = new Grid { ColumnDefinitions = new ColumnDefinitions("16,34,*,128,176"), Margin = new Thickness(0, 6), Opacity = d.Online ? 1 : 0.5 };
        var dot = new Ellipse { Width = 8, Height = 8, Fill = d.Online ? Good : Brush("#4A5163"), VerticalAlignment = VerticalAlignment.Center };
        if (d.Online) dot.Effect = new DropShadowEffect { BlurRadius = 8, Color = Color.Parse("#19F58C"), OffsetX = 0, OffsetY = 0, Opacity = 0.8 };
        g.Children.Add(dot);
        var glyph = new TextBlock { Text = Classifier.Glyph(d.Kind), FontFamily = Glyphs, FontSize = 18, VerticalAlignment = VerticalAlignment.Center, Foreground = KindBrush(d.Kind) };
        Grid.SetColumn(glyph, 1);
        g.Children.Add(glyph);
        var names = new StackPanel { VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 10, 0) };
        names.Children.Add(new TextBlock { Text = d.Name, FontWeight = FontWeight.SemiBold, FontSize = 13.5, TextTrimming = TextTrimming.CharacterEllipsis });
        var sub = d.Online ? d.Subtitle : "Last seen " + Ago(d.LastSeen) + (d.Subtitle.Length > 0 ? "  ·  " + d.Subtitle : "");
        if (sub.Length > 0) names.Children.Add(new TextBlock { Text = sub, Classes = { "muted" }, FontSize = 11.5, TextTrimming = TextTrimming.CharacterEllipsis });
        Grid.SetColumn(names, 2);
        g.Children.Add(names);
        // IP over MAC, then the type: fixed widths so every row lines up.
        var addr = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
        addr.Children.Add(new TextBlock { Text = d.Ip, FontFamily = Mono, FontSize = 12.5 });
        if (d.Mac.Length > 0) addr.Children.Add(new TextBlock { Text = Device.Pretty(d.Mac), FontFamily = Mono, FontSize = 10.5, Foreground = Muted });
        Grid.SetColumn(addr, 3);
        g.Children.Add(addr);
        var pill = Pill(d.KindText, KindClass(d.Kind));
        ((TextBlock)pill.Child!).TextTrimming = TextTrimming.CharacterEllipsis;
        ToolTip.SetTip(pill, d.KindText);
        pill.Margin = new Thickness(8, 0, 4, 0);
        pill.HorizontalAlignment = HorizontalAlignment.Right;
        Grid.SetColumn(pill, 4);
        g.Children.Add(pill);
        return g;
    }

    internal static string KindClass(DeviceKind k) => k switch
    {
        DeviceKind.ThisPc or DeviceKind.Router => "good",
        DeviceKind.Printer => "warn",
        DeviceKind.Unknown => "plain",
        _ => "info",
    };

    internal static IBrush KindBrush(DeviceKind k) => k switch
    {
        DeviceKind.ThisPc or DeviceKind.Router or DeviceKind.NetworkGear => Brush("#19F58C"),
        DeviceKind.Printer => Brush("#F5B14C"),
        DeviceKind.Phone => Brush("#B98CFF"),
        DeviceKind.Media or DeviceKind.GameConsole => Brush("#FF7AB6"),
        DeviceKind.SmartHome or DeviceKind.Camera => Brush("#FFD23F"),
        DeviceKind.Unknown => Muted,
        _ => Brush("#00C8FF"),
    };

    internal static string Ago(DateTime t)
    {
        var s = DateTime.Now - t;
        if (s.TotalMinutes < 2) return "just now";
        if (s.TotalHours < 1) return $"{(int)s.TotalMinutes} minutes ago";
        if (s.TotalDays < 1) return $"{(int)s.TotalHours} hour{((int)s.TotalHours == 1 ? "" : "s")} ago";
        if (s.TotalDays < 14) return $"{(int)s.TotalDays} day{((int)s.TotalDays == 1 ? "" : "s")} ago";
        return t.ToString("d MMM yyyy");
    }

    // ---------- Details ----------

    private void ShowDetails()
    {
        var d = _selected;
        if (d is null)
        {
            var hint = new StackPanel { Spacing = 10, VerticalAlignment = VerticalAlignment.Center };
            hint.Children.Add(new TextBlock { Text = "", FontFamily = Glyphs, FontSize = 40, Foreground = Brush("#2B7C9A"), HorizontalAlignment = HorizontalAlignment.Center });
            hint.Children.Add(new TextBlock { Text = "Pick a device to see everything it gave away: maker, model, names, open ports, its web page and why it was recognised.", Classes = { "muted" }, TextWrapping = TextWrapping.Wrap, TextAlignment = TextAlignment.Center });
            _details.Child = hint;
            return;
        }

        var stack = new StackPanel { Spacing = 4 };
        var head = new Grid { ColumnDefinitions = new ColumnDefinitions("Auto,*"), Margin = new Thickness(0, 0, 0, 8) };
        head.Children.Add(new Border
        {
            Width = 48, Height = 48, CornerRadius = new CornerRadius(12), Background = Brush("#10202A"), Margin = new Thickness(0, 0, 12, 0),
            Child = new TextBlock { Text = Classifier.Glyph(d.Kind), FontFamily = Glyphs, FontSize = 24, Foreground = KindBrush(d.Kind), HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center },
        });
        var titles = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
        titles.Children.Add(new TextBlock { Text = d.Name, FontSize = 17, FontWeight = FontWeight.Bold, TextWrapping = TextWrapping.Wrap });
        var pills = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 6, Margin = new Thickness(0, 4, 0, 0) };
        pills.Children.Add(Pill(d.KindText, KindClass(d.Kind)));
        pills.Children.Add(Pill(d.Online ? (d.LatencyMs >= 0 ? $"Online · {d.LatencyMs} ms" : "Online") : "Offline", d.Online ? "good" : "plain"));
        titles.Children.Add(pills);
        Grid.SetColumn(titles, 1);
        head.Children.Add(titles);
        stack.Children.Add(head);

        if (d.Why.Count > 0)
            stack.Children.Add(new TextBlock { Text = "Recognised because " + string.Join("; ", d.Why) + ".", Classes = { "muted" }, FontSize = 12, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 8) });

        void Field(string label, string value, bool mono = false)
        {
            if (value.Length == 0) return;
            var g = new Grid { ColumnDefinitions = new ColumnDefinitions("104,*"), Margin = new Thickness(0, 3) };
            g.Children.Add(new TextBlock { Text = label, Classes = { "muted" }, FontSize = 12 });
            var v = new SelectableTextBlock { Text = value, TextWrapping = TextWrapping.Wrap, FontSize = 12.5 };
            if (mono) v.FontFamily = Mono;
            Grid.SetColumn(v, 1);
            g.Children.Add(v);
            stack.Children.Add(g);
        }

        Field("IP address", d.Ip + (d.IsGateway ? "  (gateway)" : ""), mono: true);
        Field("MAC address", d.Mac.Length > 0 ? Device.Pretty(d.Mac) + (d.RandomMac ? "  (private)" : "") : "", mono: true);
        Field("Maker", d.Vendor.Length > 0 ? d.Vendor : d.RandomMac ? "Hidden: the device uses a private, random MAC address" : "");
        Field("Model", string.Join(" ", new[] { d.Manufacturer, d.Model }.Where(s => s.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase)));
        Field("Host names", string.Join("\n", d.HostNames));
        Field("Workgroup", d.NetBiosGroup);
        Field("System", d.Os);
        Field("Open ports", string.Join("\n", d.Ports.Select(p => $"{p}  {PortNames.Name(p)}")));
        Field("Services", string.Join("\n", d.Services.Select(ServiceName)));
        Field("Web page", d.HttpTitle);
        Field("Web server", d.HttpServer);
        Field("UPnP", string.Join("\n", new[] { d.SsdpType, d.SsdpServer }.Where(s => s.Length > 0)));
        Field("SNMP", d.SnmpDescr);
        Field("First seen", d.FirstSeen == default ? "" : d.FirstSeen.ToString("d MMM yyyy HH:mm"));
        Field("Last seen", d.Online ? "Now" : d.LastSeen.ToString("d MMM yyyy HH:mm") + "  (" + Ago(d.LastSeen) + ")");

        // Rename
        var rename = new Grid { ColumnDefinitions = new ColumnDefinitions("*,Auto"), Margin = new Thickness(0, 12, 0, 0) };
        var box = new TextBox { Text = d.Label, PlaceholderText = "Give it a name…" };
        var save = new Button { Content = "Save name", Margin = new Thickness(8, 0, 0, 0) };
        void SaveName()
        {
            d.Label = (box.Text ?? "").Trim();
            _store.Save();
            Refresh();
        }

        save.Click += (_, _) => SaveName();
        box.KeyDown += (_, e) =>
        {
            if (e.Key == Avalonia.Input.Key.Enter) SaveName();
        };
        rename.Children.Add(box);
        Grid.SetColumn(save, 1);
        rename.Children.Add(save);
        stack.Children.Add(rename);

        // Actions
        var acts = new WrapPanel { Margin = new Thickness(0, 10, 0, 0), ItemSpacing = 6, LineSpacing = 6 };
        Button Act(string text, string tip, Action run)
        {
            var b = new Button { Content = text, MinHeight = 32, Padding = new Thickness(12, 5) };
            ToolTip.SetTip(b, tip);
            b.Click += (_, _) =>
            {
                if (!SelfTestMode) run();
            };
            acts.Children.Add(b);
            return b;
        }

        if (d.Online)
        {
            var web = PortNames.Web.FirstOrDefault(d.Ports.Contains);
            if (web > 0)
            {
                var url = $"{(PortNames.IsHttps(web) ? "https" : "http")}://{d.Ip}{(web is 80 or 443 ? "" : ":" + web)}/";
                Act("Open web page", url, () => Open(url));
            }

            if (d.Has(3389) && !d.IsSelf) Act("Remote Desktop", "Connect with Remote Desktop (mstsc)", () => Start("mstsc.exe", "/v:" + d.Ip));
            if (d.Has(445) && !d.IsSelf) Act("Open shares", $@"Open \\{d.Ip} in File Explorer", () => Start("explorer.exe", $@"\\{d.Ip}"));
        }

        Act("Copy details", "Copy everything above as text", async () =>
        {
            if (Clipboard is { } cb) await Avalonia.Input.Platform.ClipboardExtensions.SetTextAsync(cb, d.Details());
            ShowNotice("Details copied.", good: true);
        });
        if (!d.Online && d.Mac.Length == 12 && !d.RandomMac)
            Act("Wake up", "Send a Wake-on-LAN packet (the device must have it turned on)", () =>
            {
                var bc = _ranges.FirstOrDefault(r => IPAddress.TryParse(d.Ip, out var a) && r.Contains(a))?.Broadcast;
                ShowNotice(Probes.Wake(d.Mac, bc) ? $"Wake-on-LAN packet sent to {Device.Pretty(d.Mac)}. Scan again in a minute." : "Couldn't send the Wake-on-LAN packet.", good: true);
            });
        if (!d.Online)
            Act("Forget", "Remove it from the list", () =>
            {
                _store.Forget(d);
                _store.Save();
                _selected = null;
                Refresh();
            });
        stack.Children.Add(acts);

        _details.Child = new ScrollViewer { Content = stack, HorizontalScrollBarVisibility = Avalonia.Controls.Primitives.ScrollBarVisibility.Disabled };
    }

    internal static string ServiceName(string s) => s switch
    {
        "_ipp._tcp" or "_ipps._tcp" => "Printing (IPP)",
        "_printer._tcp" => "Printing (LPD)",
        "_pdl-datastream._tcp" => "Printing (raw)",
        "_uscan._tcp" or "_scanner._tcp" => "Scanning",
        "_airplay._tcp" => "AirPlay",
        "_raop._tcp" => "AirPlay audio",
        "_googlecast._tcp" => "Google Cast",
        "_spotify-connect._tcp" => "Spotify Connect",
        "_sonos._tcp" => "Sonos",
        "_amzn-wplay._tcp" => "Fire TV casting",
        "_hap._tcp" or "_homekit._tcp" => "HomeKit",
        "_matter._tcp" => "Matter",
        "_hue._tcp" => "Philips Hue",
        "_esphomelib._tcp" => "ESPHome",
        "_home-assistant._tcp" => "Home Assistant",
        "_smb._tcp" => "File sharing (SMB)",
        "_afpovertcp._tcp" => "Apple file sharing",
        "_ssh._tcp" or "_sftp-ssh._tcp" => "SSH",
        "_http._tcp" => "Web page",
        "_device-info._tcp" => "Device info",
        "_workstation._tcp" => "Workstation",
        "_companion-link._tcp" => "Apple companion link",
        "_rdlink._tcp" => "Remote Desktop link",
        "_apple-mobdev2._tcp" => "iPhone / iPad sync",
        "_androidtvremote2._tcp" => "Android TV remote",
        "_nvstream._tcp" => "NVIDIA GameStream",
        _ => s,
    };

    private static void Open(string url)
    {
        try { Process.Start(new ProcessStartInfo(url) { UseShellExecute = true }); }
        catch { }
    }

    private static void Start(string exe, string args)
    {
        try { Process.Start(new ProcessStartInfo(exe, args) { UseShellExecute = true }); }
        catch { }
    }
}
