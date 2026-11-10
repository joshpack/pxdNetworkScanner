using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace pxdNetworkScanner.Core;

/// <summary>A range of IPv4 addresses to scan, usually the local network of one adapter.</summary>
public sealed record ScanRange(string Label, uint First, uint Last, IPAddress? LocalIp = null, string LocalMac = "", IPAddress? Gateway = null, IPAddress? Broadcast = null, string Adapter = "")
{
    public const int MaxAddresses = 4096;

    public int Count => (int)Math.Min(Last - First + 1, int.MaxValue);

    public IEnumerable<IPAddress> Addresses()
    {
        for (var a = First; a <= Last && a != 0; a++) yield return FromUint(a);
    }

    public bool Contains(IPAddress ip) => ToUint(ip) is var v && v >= First && v <= Last;

    /// <summary>"192.168.1.0/24", or "172.16.0.20 - 172.16.0.80" for a custom range.</summary>
    public string Text
    {
        get
        {
            var span = Last - First + 1;
            for (var bits = 30; bits >= 16; bits--)
            {
                var size = 1u << (32 - bits);
                if (span == size - 2 && (First - 1) % size == 0) return $"{FromUint(First - 1)}/{bits}";
            }

            return First == Last ? FromUint(First).ToString() : $"{FromUint(First)} - {FromUint(Last)}";
        }
    }

    public static uint ToUint(IPAddress ip)
    {
        var b = ip.MapToIPv4().GetAddressBytes();
        return (uint)(b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]);
    }

    public static IPAddress FromUint(uint v) => new([(byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8), (byte)v]);

    /// <summary>
    /// Reads what the user typed: "192.168.1.0/24", "172.16.0.1-254", "172.16.0.20-172.16.0.80" or one address.
    /// Null (with a reason) when it isn't one of those or is bigger than <see cref="MaxAddresses"/>.
    /// </summary>
    public static ScanRange? Parse(string text, out string error)
    {
        error = "";
        var t = text.Trim().Replace(" ", "");
        try
        {
            uint first, last;
            if (t.Contains('/'))
            {
                var p = t.Split('/');
                var bits = int.Parse(p[1]);
                if (bits is < 8 or > 32) throw new FormatException();
                var ip = ToUint(IPAddress.Parse(p[0]));
                var mask = bits == 32 ? uint.MaxValue : ~(uint.MaxValue >> bits);
                var net = ip & mask;
                var bc = net | ~mask;
                (first, last) = bits >= 31 ? (net, bc) : (net + 1, bc - 1);
            }
            else if (t.Contains('-'))
            {
                var p = t.Split('-');
                first = ToUint(IPAddress.Parse(p[0]));
                last = p[1].Contains('.') ? ToUint(IPAddress.Parse(p[1])) : (first & 0xFFFFFF00) | uint.Parse(p[1]);
                if (p[1].Contains('.') is false && uint.Parse(p[1]) > 255) throw new FormatException();
            }
            else
            {
                first = last = ToUint(IPAddress.Parse(t));
            }

            if (last < first) (first, last) = (last, first);
            if (last - first + 1 > MaxAddresses)
            {
                error = $"That's {last - first + 1:N0} addresses; up to {MaxAddresses:N0} can be scanned at once (a /20).";
                return null;
            }

            return new ScanRange(text.Trim(), first, last);
        }
        catch
        {
            error = "Type a range like 192.168.1.0/24, 192.168.1.1-254 or 172.16.0.20-172.16.0.80.";
            return null;
        }
    }

    /// <summary>
    /// The local network of every connected IPv4 adapter, the one with a default gateway first. A network bigger than a /24
    /// is cut down to the /24 around this PC, so a scan stays quick (a custom range can go up to a /20).
    /// </summary>
    public static List<ScanRange> Local()
    {
        var list = new List<(ScanRange Range, bool HasGateway, long Speed)>();
        NetworkInterface[] nics;
        try { nics = NetworkInterface.GetAllNetworkInterfaces(); }
        catch { return []; }
        foreach (var nic in nics)
        {
            if (nic.OperationalStatus != OperationalStatus.Up || nic.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel) continue;
            IPInterfaceProperties props;
            try { props = nic.GetIPProperties(); }
            catch { continue; }
            var gw = props.GatewayAddresses.Select(g => g.Address).FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork && !a.Equals(IPAddress.Any));
            foreach (var u in props.UnicastAddresses)
            {
                if (u.Address.AddressFamily != AddressFamily.InterNetwork || IPAddress.IsLoopback(u.Address)) continue;
                var ip = ToUint(u.Address);
                if ((ip >> 16) == 0xA9FE) continue;   // 169.254.x.x: no DHCP answer, nothing to scan
                var bits = u.PrefixLength is > 0 and <= 32 ? u.PrefixLength : 24;
                var mask = bits == 32 ? uint.MaxValue : ~(uint.MaxValue >> bits);
                var bc = (ip & mask) | ~mask;
                if (bits < 24) bits = 24;
                var smask = ~(uint.MaxValue >> bits);
                var net = ip & smask;
                var last = Math.Min(net | ~smask, bc);
                var first = net + 1;
                if (bits >= 31) continue;
                var mac = nic.GetPhysicalAddress().ToString();
                var name = string.IsNullOrWhiteSpace(nic.Name) ? nic.Description : nic.Name;
                var range = new ScanRange($"{name}  ·  {FromUint(net)}/{bits}", first, last - 1, u.Address, mac, gw, FromUint(bc), name);
                list.Add((range, gw is not null, nic.Speed));
            }
        }

        // Real adapters before virtual switches (Hyper-V, WSL, VirtualBox, VPNs).
        static bool Virtual(ScanRange r) => r.Adapter.Contains("vEthernet", StringComparison.OrdinalIgnoreCase) || r.Adapter.Contains("VirtualBox", StringComparison.OrdinalIgnoreCase)
                                            || r.Adapter.Contains("VMware", StringComparison.OrdinalIgnoreCase) || r.Adapter.Contains("WSL", StringComparison.OrdinalIgnoreCase);
        return list.OrderByDescending(x => x.HasGateway).ThenBy(x => Virtual(x.Range)).ThenByDescending(x => x.Speed).Select(x => x.Range)
            .DistinctBy(r => (r.First, r.Last)).ToList();
    }
}
