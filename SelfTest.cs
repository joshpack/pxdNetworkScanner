using System.Net;
using System.Text;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Headless;
using Avalonia.LogicalTree;
using Avalonia.Media.Imaging;
using Avalonia.Threading;
using pxdNetworkScanner.Core;
using pxdNetworkScanner.Views;

namespace pxdNetworkScanner;

/// <summary>
/// --self-test DIR [--sample] [--no-scan]: checks range parsing, the MAC maker table, the NetBIOS / SNMP / mDNS / UPnP
/// parsers on recorded answers, the device guesses, the device store and the exports, runs one real scan of this
/// PC's network (unless --no-scan), and renders the window to PNGs on the headless platform (nothing on screen).
/// --sample shows a made-up network, for README screenshots. Exit code 0 = all passed.
/// </summary>
internal static class SelfTest
{
    public static string? Dir { get; set; }
    public static bool Sample { get; set; }
    public static bool Live { get; set; } = true;
    public static int ExitCode { get; private set; } = 1;

    private static readonly StringBuilder R = new();
    private static int _failed;

    private static void Check(string name, bool ok, string? detail = null)
    {
        R.AppendLine($"[{(ok ? "PASS" : "FAIL")}] {name}{(detail is null ? "" : ": " + detail)}");
        if (!ok) _failed++;
    }

    public static async Task RunAsync()
    {
        R.AppendLine($"pxd Network Scanner {typeof(SelfTest).Assembly.GetName().Version?.ToString(3)} self-test, {DateTime.Now:yyyy-MM-dd HH:mm}");
        R.AppendLine();
        try
        {
            Ranges();
            Makers();
            Parsers();
            Guesses();
            StoreAndExports();
            List<Device>? live = null;
            if (Live && !Sample) live = await LiveScan();
            await Render(Sample || live is null ? SampleNetwork() : live);
            await Placement();
            SingleInstanceCheck();
            await UpdateChecks();
        }
        catch (Exception ex)
        {
            Check("no crash", false, ex.ToString());
        }

        R.AppendLine();
        R.AppendLine(_failed == 0 ? "RESULT: all checks passed" : $"RESULT: {_failed} check(s) FAILED");
        ExitCode = _failed == 0 ? 0 : 1;
        await File.WriteAllTextAsync(Path.Combine(Dir!, "report.txt"), R.ToString());
    }

    /// <summary>pxdUpdate: skipped for --self-test and dev builds; a fake release on a local HttpListener updates a temp folder.</summary>
    private static async Task UpdateChecks()
    {
        R.AppendLine("== Update before start (local fake release, temp folders) ==");
        foreach (var (name, ok, detail) in await SelfTestUpdate.RunAsync(Dir!))
            Check(name, ok, detail.Length > 0 ? detail : null);
        R.AppendLine();
    }

    private static void Ranges()
    {
        R.AppendLine("== Ranges ==");
        var r = ScanRange.Parse("192.168.1.0/24", out _);
        Check("/24 is .1 to .254", r is { Count: 254 } && r.Text == "192.168.1.0/24" && ScanRange.FromUint(r.First).ToString() == "192.168.1.1", r?.Text);
        r = ScanRange.Parse("172.16.0.20-172.16.0.80", out _);
        Check("Full range", r is { Count: 61 } && r.Text == "172.16.0.20 - 172.16.0.80", r?.Text);
        r = ScanRange.Parse("172.16.0.1-254", out _);
        Check("Short range", r is { Count: 254 } && r.Contains(IPAddress.Parse("172.16.0.254")) && !r.Contains(IPAddress.Parse("172.16.1.1")));
        r = ScanRange.Parse("192.168.1.77", out _);
        Check("One address", r is { Count: 1 });
        Check("Too big is refused", ScanRange.Parse("172.16.0.0/16", out var why) is null && why.Contains("4,096"), why);
        Check("Nonsense is refused", ScanRange.Parse("my network", out why) is null && why.Length > 10);
        var local = ScanRange.Local();
        Check("This PC's networks found", local.Count > 0, string.Join("; ", local.Select(l => $"{l.Label} (me {l.LocalIp}, gw {l.Gateway})")));
        R.AppendLine();
    }

    private static void Makers()
    {
        R.AppendLine("== MAC makers ==");
        Check("Maker table loaded", Vendors.Count > 50_000, Vendors.Count.ToString("N0"));
        Check("Brother", Vendors.Lookup("3C2AF4112233").Contains("Brother"), Vendors.Lookup("3C2AF4112233"));
        Check("Raspberry Pi", Vendors.Lookup("B827EB000001").Contains("Raspberry"), Vendors.Lookup("B827EB000001"));
        Check("Proxmox VMs", Vendors.Lookup("BC2411AABBCC") == "Proxmox");
        Check("VirtualBox (registered under another name)", Vendors.Lookup("080027AABBCC") == "VirtualBox");
        Check("Random MAC noticed", new Device { Mac = "DA1122334455" }.RandomMac && !new Device { Mac = "3C2AF4112233" }.RandomMac);
        R.AppendLine();
    }

    private static byte[] Tlv(byte tag, params byte[][] parts)
    {
        var body = parts.SelectMany(p => p).ToArray();
        return body.Length < 128 ? [tag, (byte)body.Length, .. body] : [tag, 0x81, (byte)body.Length, .. body];
    }

    private static void Name(List<byte> p, string name)
    {
        foreach (var l in name.Split('.'))
        {
            var b = Encoding.UTF8.GetBytes(l);
            p.Add((byte)b.Length);
            p.AddRange(b);
        }

        p.Add(0);
    }

    private static void Parsers()
    {
        R.AppendLine("== Reading answers (recorded examples) ==");
        // NetBIOS node status: header, the query name, type/class/TTL/length, then the name table and the MAC.
        var nb = new List<byte> { 0x50, 0x00, 0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0 };
        nb.AddRange(Probes.NetBiosQuery(0).Skip(12).Take(34));
        nb.AddRange([0, 0x21, 0, 1, 0, 0, 0, 0]);
        var table = new List<byte> { 3 };
        void Entry(string n, byte suffix, bool group)
        {
            table.AddRange(Encoding.ASCII.GetBytes(n.PadRight(15)));
            table.Add(suffix);
            table.AddRange([(byte)(group ? 0x84 : 0x04), 0]);
        }

        Entry("DESKTOP-ALEX", 0, false);
        Entry("WORKGROUP", 0, true);
        Entry("DESKTOP-ALEX", 0x20, false);
        table.AddRange([0x3C, 0x2A, 0xF4, 1, 2, 3]);
        nb.AddRange([(byte)(table.Count >> 8), (byte)table.Count]);
        nb.AddRange(table);
        var (name, group) = Probes.ParseNetBios(nb.ToArray());
        Check("NetBIOS name and workgroup", name == "DESKTOP-ALEX" && group == "WORKGROUP", $"{name} / {group}");

        // SNMP: the query is well-formed BER, and a printer's answer reads back.
        var q = Probes.SnmpQuery(0x1234);
        Check("SNMP query is one BER sequence", q[0] == 0x30 && q[1] == q.Length - 2, Convert.ToHexString(q));
        byte[] Bind(byte[] oid, string text) => Tlv(0x30, Tlv(0x06, oid), Tlv(0x04, Encoding.UTF8.GetBytes(text)));
        var answer = Tlv(0x30, Tlv(0x02, [1]), Tlv(0x04, "public"u8.ToArray()),
            Tlv(0xA2, Tlv(0x02, [0x12, 0x34]), Tlv(0x02, [0]), Tlv(0x02, [0]),
                Tlv(0x30, Bind([0x2B, 6, 1, 2, 1, 1, 1, 0], "Brother NC-8300w, Firmware Ver.1.10  (19.07.11),MID 8C5-F40,FID 2"),
                    Bind([0x2B, 6, 1, 2, 1, 1, 5, 0], "BRW3C2AF4010203"), Bind([0x2B, 6, 1, 2, 1, 0x19, 3, 2, 1, 3, 1], "Brother HL-L2350DW series"))));
        var (descr, sysName, device) = Probes.ParseSnmp(answer);
        Check("SNMP printer answer", descr.StartsWith("Brother NC-8300w") && sysName == "BRW3C2AF4010203" && device == "Brother HL-L2350DW series", $"{descr} | {sysName} | {device}");

        // mDNS: a Chromecast's answer with PTR, SRV, TXT and A records.
        var md = new List<byte> { 0, 0, 0x84, 0, 0, 0, 0, 4, 0, 0, 0, 0 };
        void Rr(string rname, ushort type, byte[] data)
        {
            Name(md, rname);
            md.AddRange([(byte)(type >> 8), (byte)type, 0x80, 1, 0, 0, 0x11, 0x94, (byte)(data.Length >> 8), (byte)data.Length]);
            md.AddRange(data);
        }

        var inst = new List<byte>();
        Name(inst, "Chromecast-Ultra-8a1b._googlecast._tcp.local");
        Rr("_googlecast._tcp.local", 12, inst.ToArray());
        var srv = new List<byte> { 0, 0, 0, 0, 0x1F, 0x49 };
        Name(srv, "8a1b2c3d.local");
        Rr("Chromecast-Ultra-8a1b._googlecast._tcp.local", 33, srv.ToArray());
        var txt = new List<byte>();
        foreach (var kv in new[] { "id=8a1b", "md=Chromecast Ultra", "fn=Living Room TV" })
        {
            txt.Add((byte)kv.Length);
            txt.AddRange(Encoding.UTF8.GetBytes(kv));
        }

        Rr("Chromecast-Ultra-8a1b._googlecast._tcp.local", 16, txt.ToArray());
        Rr("8a1b2c3d.local", 1, [192, 168, 1, 30]);
        var a = new Announced();
        Discovery.ParseMdns(md.ToArray(), a);
        Check("Bonjour: service, name, model, host", a.Services.Contains("_googlecast._tcp") && a.FriendlyName == "Living Room TV" && a.Model == "Chromecast Ultra" && a.Host == "8a1b2c3d.local",
            $"{string.Join(",", a.Services)} | {a.FriendlyName} | {a.Model} | {a.Host}");
        Check("Bonjour query lists every service type", Discovery.MdnsQuery().Length > 400 && Discovery.MdnsQuery()[5] == Discovery.MdnsServices.Length);

        // UPnP device description
        var u = new Announced();
        Discovery.ApplyDescription(u, """
            <?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0"><specVersion><major>1</major></specVersion>
            <device><deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType><friendlyName>[TV] Samsung Q80 Series (55)</friendlyName>
            <manufacturer>Samsung Electronics</manufacturer><modelName>QN55Q80BAFXZA</modelName><modelNumber>AllShare1.0</modelNumber></device></root>
            """);
        Check("UPnP description", u.FriendlyName == "[TV] Samsung Q80 Series (55)" && u.Manufacturer == "Samsung Electronics" && u.Model.StartsWith("QN55Q80BAFXZA") && u.DeviceType == "MediaRenderer",
            $"{u.FriendlyName} | {u.Manufacturer} | {u.Model} | {u.DeviceType}");
        R.AppendLine();
    }

    private static Device D(string ip, string mac, string vendor, params int[] ports)
    {
        var d = new Device { Ip = ip, Mac = mac, Vendor = vendor, Ports = ports.ToList(), Online = true, FirstSeen = DateTime.Now.AddDays(-20), LastSeen = DateTime.Now };
        return d;
    }

    private static Device Done(Device d)
    {
        Scanner.Finish(d);
        return d;
    }

    private static void Guesses()
    {
        R.AppendLine("== What each device is ==");
        void Is(string what, Device d, DeviceKind kind, string? text = null)
        {
            Scanner.Finish(d);
            Check(what, d.Kind == kind && (text is null || d.KindText == text), $"{d.Kind} \"{d.KindText}\" because {string.Join("; ", d.Why)}");
        }

        Is("Printer by port 9100", D("192.168.1.20", "3C2AF4010203", "Brother Industries", 80, 443, 631, 9100), DeviceKind.Printer, "Printer");
        Is("Printer by SNMP alone", new Device { Ip = "1.1.1.5", SnmpDescr = "HP ETHERNET MULTI-ENVIRONMENT,ROM none,JETDIRECT,JD153" }, DeviceKind.Printer);
        Is("Printer / scanner by Bonjour", new Device { Ip = "1.1.1.6", Services = ["_ipp._tcp", "_uscan._tcp"] }, DeviceKind.Printer, "Printer / scanner");
        Is("Gateway is the router", new Device { Ip = "1.1.1.1", IsGateway = true, Ports = [53, 80, 443] }, DeviceKind.Router);
        Is("Windows PC", new Device { Ip = "1.1.1.7", Ports = [135, 139, 445, 3389], Ttl = 128, NetBiosName = "DESKTOP-ALEX" }, DeviceKind.Computer, "Windows PC");
        Is("iPhone by its sync port", D("1.1.1.8", "F0989D000001", "Apple", 62078), DeviceKind.Phone, "iPhone or iPad");
        Is("Mac by its Bonjour model", new Device { Ip = "1.1.1.9", Vendor = "Apple", Model = "MacBookPro18,3", Ports = [22, 445] }, DeviceKind.Computer, "Mac");
        Is("Apple TV", new Device { Ip = "1.1.1.10", Vendor = "Apple", Model = "AppleTV11,1", Services = ["_airplay._tcp"] }, DeviceKind.Media, "Apple TV");
        Is("Private MAC with nothing open", new Device { Ip = "1.1.1.11", Mac = "DA1122334455" }, DeviceKind.Phone);
        Is("Chromecast", new Device { Ip = "1.1.1.12", Services = ["_googlecast._tcp"], Model = "Chromecast Ultra", Ports = [8008, 8009] }, DeviceKind.Media, "Chromecast / Cast device");
        Is("Google Nest speaker", new Device { Ip = "1.1.1.13", Services = ["_googlecast._tcp"], Model = "Google Nest Mini" }, DeviceKind.Media, "Smart speaker");
        Is("Synology NAS", D("1.1.1.14", "0011320A0B0C", "Synology", 80, 443, 445, 5000, 5001), DeviceKind.Storage);
        Is("Proxmox host", D("1.1.1.15", "001B21AABBCC", "Intel Corporate", 22, 8006), DeviceKind.Server, "Proxmox server");
        Is("Proxmox VM", D("1.1.1.16", "BC2411AABBCC", "Proxmox", 22, 80), DeviceKind.VirtualMachine);
        Is("Linux box with SSH", new Device { Ip = "1.1.1.17", Ports = [22], Ttl = 64 }, DeviceKind.Server);
        Is("Camera by RTSP", D("1.1.1.18", "C0563B000001", "Hangzhou Hikvision Digital", 80, 554), DeviceKind.Camera);
        Is("ESP smart plug", D("1.1.1.19", "A4CF12000001", "Espressif"), DeviceKind.SmartHome);
        Is("Xbox", new Device { Ip = "1.1.1.20", Vendor = "Microsoft", FriendlyName = "Xbox Series X" }, DeviceKind.GameConsole, "Xbox");
        Is("UniFi access point", D("1.1.1.21", "245A4C000001", "Ubiquiti", 22), DeviceKind.NetworkGear);
        Is("Nothing to go on", new Device { Ip = "1.1.1.22", Mac = "0012340A0B0C", Vendor = "Acme Widgets" }, DeviceKind.Unknown);
        Is("This PC", new Device { Ip = "1.1.1.23", IsSelf = true, Ports = [135, 445] }, DeviceKind.ThisPc);
        R.AppendLine();
    }

    private static void StoreAndExports()
    {
        R.AppendLine("== Remembered devices and exports ==");
        var file = Path.Combine(Dir!, "store-test.json");
        if (File.Exists(file)) File.Delete(file);
        var s = new DeviceStore(file);
        var first = s.Merge(Done(D("192.168.1.40", "3C2AF4010203", "Brother Industries", 9100)));
        first.Label = "Office printer";
        var range = ScanRange.Parse("192.168.1.0/24", out _)!;
        s.BeginScan(range);
        Check("A new scan starts everyone offline", !first.Online);
        var moved = s.Merge(Done(D("192.168.1.41", "3C2AF4010203", "Brother Industries", 9100)));
        Check("Same MAC on a new IP is the same device, name kept", ReferenceEquals(first, moved) && moved.Ip == "192.168.1.41" && moved.Label == "Office printer" && moved.Online && s.Items.Count == 1);
        s.Merge(Done(D("192.168.1.50", "", "", 22)));
        s.Save();
        var again = new DeviceStore(file);
        Check("Saved and read back (offline until scanned)", again.Items.Count == 2 && again.Items.All(d => !d.Online) && again.Items.Any(d => d.Label == "Office printer"));
        again.ForgetOffline();
        Check("Forget offline", again.Items.Count == 0);
        var two = new DeviceStore(null);
        two.Merge(Done(D("172.16.0.10", "5C15C5000001", "", 80)));
        two.Merge(Done(D("172.16.0.114", "5C15C5000001", "")));
        two.Merge(Done(D("172.16.0.10", "5C15C5000001", "", 80)));
        Check("One MAC on two IPs stays two devices", two.Items.Count == 2 && two.Items.Select(d => d.Ip).Distinct().Count() == 2);
        Check("Maker names tidied", Vendors.Tidy("Nintendo Co.,Ltd") == "Nintendo" && Vendors.Tidy("Quectel Wireless Solutions Co.,Ltd.") == "Quectel Wireless Solutions" && Vendors.Tidy("Apple, Inc.") == "Apple", Vendors.Tidy("Quectel Wireless Solutions Co.,Ltd."));

        var devices = SampleNetwork();
        foreach (var d in devices) Scanner.Finish(d);
        var csv = Report.Csv(devices);
        Check("CSV: a header and a line per device", csv.Split('\n', StringSplitOptions.RemoveEmptyEntries).Length == devices.Count + 1);
        var evil = Report.Csv([new Device { Ip = "1.1.1.1", Label = "=HYPERLINK(\"x\")" }]);
        Check("CSV: a name starting with = can't become a formula", evil.Contains("\"'=HYPERLINK"), evil.Split('\n')[1]);
        var html = Report.Html(devices, "192.168.1.0/24", DateTime.Now);
        Check("HTML report", html.Contains("<table") && html.Contains("Brother HL-L2350DW") && !html.Contains("<script"));
        var json = Report.JsonText(devices, "192.168.1.0/24", DateTime.Now);
        Check("JSON report", System.Text.Json.JsonDocument.Parse(json).RootElement.GetProperty("devices").GetArrayLength() == devices.Count);
        Check("Serial-number names are passed over for the model", devices.First(d => d.Ip == "192.168.1.20").Name == "Brother HL-L2350DW series", devices.First(d => d.Ip == "192.168.1.20").Name);
        Check("Text details", devices.First(d => d.Kind == DeviceKind.Printer).Details().Contains("9100 Raw printing"));
        R.AppendLine();
    }

    private static async Task<List<Device>?> LiveScan()
    {
        R.AppendLine("== A real scan of this PC's network ==");
        var range = ScanRange.Local().FirstOrDefault();
        if (range is null)
        {
            Check("Scan", false, "no network");
            return null;
        }

        var updates = 0;
        var result = await Task.Run(() => Scanner.RunAsync(range, new ScanOptions(), null, _ => Interlocked.Increment(ref updates), CancellationToken.None));
        Check($"Scanned {range.Text} in {result.Elapsed.TotalSeconds:0.0} s", result.Elapsed < TimeSpan.FromSeconds(60) && !result.Cancelled);
        Check("Found this PC", result.Devices.Any(d => d.IsSelf && d.Kind == DeviceKind.ThisPc));
        Check("Found the gateway", range.Gateway is null || result.Devices.Any(d => d.IsGateway), range.Gateway?.ToString());
        Check("Live updates while scanning", updates >= result.Devices.Count, updates.ToString());
        foreach (var d in result.Devices)
            R.AppendLine($"    {d.Ip,-15} {Device.Pretty(d.Mac),-17} {d.KindText,-28} {d.Name}  [{d.Vendor}] ports {string.Join(",", d.Ports)}{(d.Services.Count > 0 ? " svc " + string.Join(",", d.Services) : "")}{(d.Model.Length > 0 ? " model " + d.Model : "")}");

        // Stopping a scan part-way stops it quickly.
        using var stop = new CancellationTokenSource(600);
        var clock = System.Diagnostics.Stopwatch.StartNew();
        var cut = await Task.Run(() => Scanner.RunAsync(range, new ScanOptions(), null, null, stop.Token));
        Check("Stop ends the scan", cut.Cancelled && clock.Elapsed < TimeSpan.FromSeconds(8), $"{clock.Elapsed.TotalSeconds:0.0} s");
        R.AppendLine();
        return result.Devices;
    }

    /// <summary>A made-up home office network, for the screenshots.</summary>
    public static List<Device> SampleNetwork()
    {
        var now = DateTime.Now;
        Device S(string ip, string mac, string vendor, int[] ports, Action<Device>? more = null)
        {
            var d = new Device { Ip = "192.168.1." + ip, Mac = mac, Vendor = vendor, Ports = ports.ToList(), Online = true, FirstSeen = now.AddDays(-30), LastSeen = now, LatencyMs = 1 + ip.Length };
            more?.Invoke(d);
            return d;
        }

        return
        [
            S("1", "245A4C1A2B01", "Ubiquiti", [22, 53, 80, 443], d => { d.IsGateway = true; d.FriendlyName = "Dream Machine Pro"; d.Model = "UDM-Pro"; d.HttpTitle = "UniFi OS"; d.Ttl = 64; }),
            S("2", "245A4C1A2B02", "Ubiquiti", [22], d => { d.SnmpDescr = "UniFi AP U6-Pro 6.6.77"; d.DnsName = "U6-Pro-Hall.lan"; }),
            S("10", "D85ED3A1B2C3", "GIGA-BYTE", [135, 139, 445, 5357], d => { d.IsSelf = true; d.NetBiosName = "WORKSTATION-07"; d.LatencyMs = 0; }),
            S("11", "00D8612F3E4D", "Micro-Star INTL", [135, 139, 445, 3389, 5357], d => { d.NetBiosName = "DESKTOP-ALEX"; d.NetBiosGroup = "WORKGROUP"; d.Ttl = 128; }),
            S("12", "A0C589334455", "Intel Corporate", [135, 139, 445], d => { d.NetBiosName = "LAPTOP-SAM"; d.NetBiosGroup = "WORKGROUP"; d.Ttl = 128; }),
            S("20", "3C2AF4010203", "Brother Industries", [80, 443, 515, 631, 9100], d => { d.SnmpDescr = "Brother NC-8300w, Firmware Ver.1.10"; d.Model = "HL-L2350DW series"; d.Manufacturer = "Brother"; d.HttpTitle = "Brother HL-L2350DW series"; d.Services = ["_ipp._tcp", "_pdl-datastream._tcp", "_printer._tcp"]; d.MdnsName = "BRW3C2AF4010203.local"; }),
            S("21", "7C4D8F112233", "HP Inc", [80, 443, 631, 8080, 9100], d => { d.Model = "OfficeJet Pro 9015e"; d.Manufacturer = "HP"; d.HttpTitle = "HP OfficeJet Pro 9015e"; d.Services = ["_ipp._tcp", "_uscan._tcp"]; d.FriendlyName = "HP OfficeJet Pro 9015e"; }),
            S("30", "F4F5D8AA0101", "Google", [8008, 8009, 8443], d => { d.FriendlyName = "Living Room TV"; d.Model = "Chromecast with Google TV"; d.Services = ["_googlecast._tcp"]; }),
            S("31", "5CAAFD010203", "Sonos", [1400], d => { d.FriendlyName = "Kitchen"; d.Model = "Sonos One"; d.Manufacturer = "Sonos, Inc."; d.SsdpType = "ZonePlayer"; }),
            S("32", "F0B3EC0A0B0C", "Apple", [7000], d => { d.FriendlyName = "Bedroom Apple TV"; d.Model = "AppleTV11,1"; d.Services = ["_airplay._tcp", "_raop._tcp"]; d.MdnsName = "Bedroom-Apple-TV.local"; }),
            S("40", "F0989D445566", "Apple", [62078], d => { d.MdnsName = "Alexs-iPhone.local"; }),
            S("41", "DA7F3C112233", "", [], d => { d.DnsName = "Galaxy-S24.lan"; }),
            S("50", "001132AB12CD", "Synology", [80, 443, 445, 5000, 5001], d => { d.NetBiosName = "NAS01"; d.HttpTitle = "DiskStation"; d.Model = "DS923+"; }),
            S("51", "001B21C0FFEE", "Intel Corporate", [22, 8006], d => { d.HttpTitle = "pve - Proxmox Virtual Environment"; d.DnsName = "pve.lan"; d.Ttl = 64; }),
            S("52", "BC2411A1B2C3", "Proxmox", [22, 80], d => { d.DnsName = "docker01.lan"; d.HttpServer = "nginx"; d.Ttl = 64; }),
            S("60", "C0563B998877", "Hangzhou Hikvision Digital", [80, 554], d => { d.HttpTitle = "Driveway"; }),
            S("61", "ECB5FA0A1B2C", "Signify", [80, 443], d => { d.FriendlyName = "Hue Bridge"; d.Services = ["_hue._tcp", "_hap._tcp"]; }),
            S("62", "A4CF12D4E5F6", "Espressif", [], d => { d.DnsName = "plug-garage.lan"; }),
            S("70", "7CED8D121314", "Microsoft", [], d => { d.FriendlyName = "Xbox Series X"; }),
            S("90", "F8BC12AA00BB", "Dell", [135, 139, 445], d => { d.Label = "Old laptop"; d.NetBiosName = "LAPTOP-OLD"; d.Online = false; d.LastSeen = now.AddDays(-3).AddHours(-2); }),
            S("95", "00E04C6B5A49", "Realtek Semiconductor", [], d => { d.Online = false; d.LastSeen = now.AddDays(-9); }),
        ];
    }

    private static async Task Render(List<Device> devices)
    {
        R.AppendLine("== Window ==");
        // Opening shows the start choices: one button per network of this PC, plus another network or range.
        var first = new MainWindow(new DeviceStore(null), showStart: true)
        {
            WindowStartupLocation = WindowStartupLocation.Manual,
            Position = new PixelPoint(-30000, -30000),
            ShowActivated = false,
            ShowInTaskbar = false,
            SelfTestMode = true,
        };
        first.Show();
        first.UpdateLayout();
        await Task.Delay(150);
        AvaloniaHeadlessPlatform.ForceRenderTimerTick();
        var startButtons = first.GetLogicalDescendants().OfType<Button>().Count(b => b.IsEffectivelyVisible && (b.Content is Grid || b.Content as string == "Scan") && b.Classes.Contains("pxd-caption") is false);
        Check("Opens on the start choices, without scanning", first.ShowingStart && !first.Scanning && first.Store.Items.Count == 0);
        Check("A choice per network plus another range", startButtons >= ScanRange.Local().Count + 1, $"{startButtons} buttons, {ScanRange.Local().Count} network(s)");
        if (!Sample)
        {
            using var sbmp = new RenderTargetBitmap(new PixelSize(1240, 820));
            sbmp.Render(first);
            sbmp.Save(Path.Combine(Dir!, "start.png"), PngBitmapEncoderOptions.Default);
        }

        first.SetDevices([], "network", TimeSpan.Zero);
        Check("Start choices hide once there are results", !first.ShowingStart);
        var notes = Summary.Insights([new Device { Ip = "1.1.1.1", Ports = [23] }, new Device { Ip = "1.1.1.2", Ports = [21, 3389] }, Done(new Device { Ip = "1.1.1.3" })], [], []);
        Check("Summary flags Telnet, FTP, Remote Desktop and unknown devices", notes.Count == 4 && notes[0].Level == Summary.Level.Bad && notes.Any(n => n.Text.Contains("FTP")) && notes.Any(n => n.Level == Summary.Level.Info), string.Join(" / ", notes.Select(n => n.Text)));
        first.Close();

        var store = new DeviceStore(null);
        var window = new MainWindow(store, showStart: false)
        {
            WindowStartupLocation = WindowStartupLocation.Manual,
            Position = new PixelPoint(-30000, -30000),
            ShowActivated = false,
            ShowInTaskbar = false,
            SelfTestMode = true,
        };
        window.Show();
        var isSample = Sample || devices.Count == SampleNetwork().Count && devices.All(d => d.Ip.StartsWith("192.168.1."));
        window.SetDevices(devices, isSample ? "192.168.1.0/24" : ScanRange.Local().FirstOrDefault()?.Text ?? "network", TimeSpan.FromSeconds(6.4), isSample);

        async Task Shot(string file, int group, Func<Device, bool>? select)
        {
            window.ShowGroup(group);
            if (select is not null && window.Visible().FirstOrDefault(select) is { } pick)
                window.GetLogicalDescendants().OfType<ListBox>().First().SelectedItem = pick;
            window.Width = 1240;
            window.Height = 820;
            window.UpdateLayout();
            await Task.Delay(150);
            await Dispatcher.UIThread.InvokeAsync(window.UpdateLayout, DispatcherPriority.Background);
            AvaloniaHeadlessPlatform.ForceRenderTimerTick();
            using var bmp = new RenderTargetBitmap(new PixelSize(1240, 820));
            bmp.Render(window);
            var path = Path.Combine(Dir!, file + ".png");
            bmp.Save(path, PngBitmapEncoderOptions.Default);
            Check($"Rendered {file}", new FileInfo(path).Length > 10_000, path);
        }

        await Shot("devices", 0, d => d.Kind == DeviceKind.Printer);
        await Shot("computers", 1, d => d.Kind == DeviceKind.Server);
        await Shot("media", 4, d => d.Kind == DeviceKind.Media);
        var counts = Enumerable.Range(0, Classifier.Groups.Length).Select(i => { window.ShowGroup(i); return window.Visible().Count(); }).ToList();
        Check("Summary card under the list after a scan", window.SummaryShowing);
        Check("Every device is in exactly one group", counts.Skip(1).Sum() == counts[0], string.Join(",", counts));

        var all = window.GetLogicalDescendants().ToList();
        Check("Title bar: icon, name, three caption buttons", window.WindowDecorations == WindowDecorations.BorderOnly
                                                                && all.OfType<TextBlock>().Any(t => t.Text == window.Title)
                                                                && all.OfType<Button>().Count(b => b.Classes.Contains("pxd-caption")) == 3);
        window.Close();
        R.AppendLine();
    }

    private static MainWindow OffScreen() => new(new DeviceStore(null), showStart: false)
    {
        WindowStartupLocation = WindowStartupLocation.Manual,
        Position = new PixelPoint(-30000, -30000),
        ShowActivated = false,
        ShowInTaskbar = false,
        SelfTestMode = true,
    };

    private static async Task Placement()
    {
        R.AppendLine("== Window placement ==");
        const string key = "selftest";
        var file = Path.Combine(Program.DataFolder, "windows.json");
        if (File.Exists(file)) File.Delete(file);
        var a = OffScreen();
        pxdStandard.pxdChrome.RememberPlacement(a, key);
        a.Show();
        await Task.Delay(50);
        a.Width = 1000;
        a.Height = 640;
        a.Position = new PixelPoint(-29000, -29000);
        a.UpdateLayout();
        await Task.Delay(50);
        a.Close();
        var json = File.Exists(file) ? await File.ReadAllTextAsync(file) : "";
        Check("Placement saved", json.Contains("\"selftest\"") && json.Contains("\"Width\":1000") && json.Contains("\"Height\":640"), json);
        var b = OffScreen();
        pxdStandard.pxdChrome.RememberPlacement(b, key);
        Check("Placement restored (size), off-screen spot ignored", b.Width == 1000 && b.Height == 640 && b.Position == new PixelPoint(-30000, -30000), $"{b.Width}x{b.Height} at {b.Position}");
        R.AppendLine();
    }

    private static void SingleInstanceCheck()
    {
        R.AppendLine("== Single instance ==");
        var name = "pxdNetworkScanner-selftest-" + Guid.NewGuid().ToString("N")[..8];
        string[]? got = null;
        using var done = new ManualResetEventSlim();
        using (SingleInstance.Listen(name, args => { got = args; done.Set(); }))
        {
            var sent = SingleInstance.Send(name, ["--from-second-start"]);
            done.Wait(3000);
            Check("Second start reaches the running copy", sent && got is ["--from-second-start"], got is null ? "nothing received" : string.Join("|", got));
        }

        R.AppendLine();
    }
}
