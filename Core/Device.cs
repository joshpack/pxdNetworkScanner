using System.Net;
using System.Text.Json.Serialization;

namespace pxdNetworkScanner.Core;

/// <summary>What a device most likely is. The order is the order of the sidebar filters.</summary>
public enum DeviceKind
{
    Unknown,
    ThisPc,
    Router,
    Computer,
    Server,
    VirtualMachine,
    Storage,
    Printer,
    Phone,
    Media,
    GameConsole,
    Camera,
    SmartHome,
    NetworkGear,
}

/// <summary>One device on the network: everything the scan learned about it, plus what was remembered from earlier scans.</summary>
public sealed class Device
{
    public string Ip { get; set; } = "";
    public string Mac { get; set; } = "";
    public string Vendor { get; set; } = "";

    /// <summary>A name the user gave it (kept across scans).</summary>
    public string Label { get; set; } = "";

    public string DnsName { get; set; } = "";
    public string NetBiosName { get; set; } = "";
    public string NetBiosGroup { get; set; } = "";
    public string MdnsName { get; set; } = "";
    public string FriendlyName { get; set; } = "";
    public string Manufacturer { get; set; } = "";
    public string Model { get; set; } = "";
    public string SsdpType { get; set; } = "";
    public string SsdpServer { get; set; } = "";
    public string SnmpDescr { get; set; } = "";
    public string SnmpName { get; set; } = "";
    public string HttpTitle { get; set; } = "";
    public string HttpServer { get; set; } = "";
    public List<int> Ports { get; set; } = [];
    public List<string> Services { get; set; } = [];

    public int Ttl { get; set; }
    public long LatencyMs { get; set; } = -1;
    public bool IsGateway { get; set; }
    public bool IsSelf { get; set; }

    public DeviceKind Kind { get; set; }
    public string KindText { get; set; } = "";
    public List<string> Why { get; set; } = [];
    public string Os { get; set; } = "";

    public DateTime FirstSeen { get; set; }
    public DateTime LastSeen { get; set; }

    /// <summary>Answered during the latest scan.</summary>
    [JsonIgnore] public bool Online { get; set; }

    /// <summary>Its MAC address is a random "private" one (phones and tablets use them per Wi-Fi network).</summary>
    [JsonIgnore] public bool RandomMac => Mac.Length >= 2 && Convert.ToByte(Mac[..2], 16) is var b && (b & 0x02) != 0;

    /// <summary>Remembered by MAC address when it has one (an IP can change hands), else by IP.</summary>
    [JsonIgnore] public string Key => Mac.Length > 0 ? Mac : "ip:" + Ip;

    [JsonIgnore] public uint IpSort => IPAddress.TryParse(Ip, out var a) && a.GetAddressBytes() is { Length: 4 } b ? (uint)(b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]) : 0;

    /// <summary>The best name it gave or has: the user's label, then what it calls itself, then its host names.</summary>
    [JsonIgnore]
    public string Name
    {
        get
        {
            if (Label.Length > 0) return Label;
            if (IsSelf) return (NetBiosName.Length > 0 ? NetBiosName : Environment.MachineName) + " (this PC)";
            foreach (var n in new[] { FriendlyName, NetBiosName, Short(MdnsName), Short(DnsName), SnmpName })
                if (n.Length > 0 && n != Ip && !LooksLikeId(n)) return n;
            if (Model.Length > 0)
            {
                var maker = (Manufacturer.Length > 0 ? Manufacturer : Vendor).Split(' ', ',')[0];
                return maker.Length > 1 && !Model.Contains(maker, StringComparison.OrdinalIgnoreCase) && !Model.Contains(',') ? maker + " " + Model : Model;
            }
            if (Vendor.Length > 0) return Vendor + " device";
            if (Kind is not (DeviceKind.Unknown or DeviceKind.ThisPc) && KindText.Length > 0) return KindText;
            return Ip;
        }
    }

    /// <summary>The second line under the name: model and maker, when they say more than the name.</summary>
    [JsonIgnore]
    public string Subtitle
    {
        get
        {
            var parts = new List<string>();
            var model = Model.Length > 0 ? Model : "";
            if (model.Length > 0 && !Name.Contains(model, StringComparison.OrdinalIgnoreCase)) parts.Add(model);
            var maker = Manufacturer.Length > 0 ? Manufacturer : Vendor;
            if (maker.Length > 0 && !parts.Any(p => p.Contains(maker, StringComparison.OrdinalIgnoreCase)) && !Name.Contains(maker, StringComparison.OrdinalIgnoreCase)) parts.Add(maker);
            if (parts.Count == 0 && RandomMac) parts.Add("Private MAC address");
            if (Os.Length > 0 && parts.Count < 2 && !parts.Any(p => p.Contains(Os, StringComparison.OrdinalIgnoreCase))) parts.Add(Os);
            return string.Join(" · ", parts);
        }
    }

    /// <summary>All the host names it answered to, without repeats.</summary>
    [JsonIgnore]
    public IEnumerable<string> HostNames => new[] { DnsName, MdnsName, NetBiosName.Length > 0 ? NetBiosName + " (NetBIOS)" : "" }
        .Where(n => n.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase);

    /// <summary>A serial number or MAC used as a name ("BRW3C2AF4010203", "ESP_A1B2C3", "android-3f2a9c01d4e5b6a7").</summary>
    public bool LooksLikeId(string name)
    {
        var n = name.Replace("-", "").Replace("_", "").Replace(":", "");
        if (Mac.Length == 12 && (n.Contains(Mac, StringComparison.OrdinalIgnoreCase) || n.Contains(Mac[6..], StringComparison.OrdinalIgnoreCase) && n.Length <= 16)) return true;
        return System.Text.RegularExpressions.Regex.IsMatch(n, "^[A-Za-z]{0,8}[0-9A-Fa-f]{10,}$") && n.Count(char.IsDigit) >= 4;
    }

    public static string Short(string host)
    {
        if (host.Length == 0) return "";
        var h = host.TrimEnd('.');
        if (h.EndsWith(".local", StringComparison.OrdinalIgnoreCase)) h = h[..^6];
        var dot = h.IndexOf('.');
        if (dot > 0 && !char.IsDigit(h[0])) h = h[..dot];
        return h;
    }

    public bool Has(params int[] ports) => ports.Any(Ports.Contains);
    public bool HasService(string type) => Services.Any(s => s.StartsWith(type, StringComparison.OrdinalIgnoreCase));

    /// <summary>Takes what the latest scan found, keeping the user's label, first-seen time and anything the scan didn't learn.</summary>
    public void Absorb(Device scan)
    {
        Ip = scan.Ip;
        if (scan.Mac.Length > 0) Mac = scan.Mac;
        static string Keep(string now, string was) => now.Length > 0 ? now : was;
        Vendor = Keep(scan.Vendor, Vendor);
        DnsName = Keep(scan.DnsName, DnsName);
        NetBiosName = Keep(scan.NetBiosName, NetBiosName);
        NetBiosGroup = Keep(scan.NetBiosGroup, NetBiosGroup);
        MdnsName = Keep(scan.MdnsName, MdnsName);
        FriendlyName = Keep(scan.FriendlyName, FriendlyName);
        Manufacturer = Keep(scan.Manufacturer, Manufacturer);
        Model = Keep(scan.Model, Model);
        SsdpType = Keep(scan.SsdpType, SsdpType);
        SsdpServer = Keep(scan.SsdpServer, SsdpServer);
        SnmpDescr = Keep(scan.SnmpDescr, SnmpDescr);
        SnmpName = Keep(scan.SnmpName, SnmpName);
        HttpTitle = Keep(scan.HttpTitle, HttpTitle);
        HttpServer = Keep(scan.HttpServer, HttpServer);
        Ports = scan.Ports;
        if (scan.Services.Count > 0) Services = scan.Services;
        Ttl = scan.Ttl;
        LatencyMs = scan.LatencyMs;
        IsGateway = scan.IsGateway;
        IsSelf = scan.IsSelf;
        LastSeen = scan.LastSeen;
        if (FirstSeen == default) FirstSeen = scan.FirstSeen;
        Online = true;
    }

    /// <summary>Plain text, for "Copy details" and the text report.</summary>
    public string Details()
    {
        var lines = new List<string> { Name, $"  Type:         {KindText}" };
        void Add(string label, string value)
        {
            if (value.Length > 0) lines.Add($"  {label + ":",-14}{value}");
        }

        Add("Status", Online ? "Online" + (LatencyMs >= 0 ? $" ({LatencyMs} ms)" : "") : "Offline, last seen " + LastSeen.ToString("yyyy-MM-dd HH:mm"));
        Add("IP address", Ip + (IsGateway ? " (default gateway)" : ""));
        Add("MAC address", Mac.Length > 0 ? Pretty(Mac) + (RandomMac ? " (private / random)" : "") : "");
        Add("Maker", Vendor);
        Add("Model", string.Join(" ", new[] { Manufacturer, Model }.Where(s => s.Length > 0).Distinct()));
        Add("Host names", string.Join(", ", HostNames));
        Add("Workgroup", NetBiosGroup);
        Add("System", Os);
        Add("Open ports", string.Join(", ", Ports.Select(p => $"{p} {PortNames.Name(p)}")));
        Add("Services", string.Join(", ", Services));
        Add("Web page", HttpTitle);
        Add("Web server", HttpServer);
        Add("UPnP", string.Join(" · ", new[] { SsdpType, SsdpServer }.Where(s => s.Length > 0)));
        Add("SNMP", SnmpDescr);
        Add("Why", string.Join("; ", Why));
        return string.Join(Environment.NewLine, lines);
    }

    public static string Pretty(string mac) => mac.Length == 12 ? string.Join(":", Enumerable.Range(0, 6).Select(i => mac.Substring(i * 2, 2))) : mac;
}
