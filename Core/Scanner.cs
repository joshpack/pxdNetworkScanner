using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace pxdNetworkScanner.Core;

public sealed class ScanOptions
{
    public int PingTimeoutMs { get; set; } = 900;
    public int PortTimeoutMs { get; set; } = 800;
    public int Parallel { get; set; } = 128;

    /// <summary>Knock on the common ports, read names, SNMP and web page titles (the part that tells devices apart).</summary>
    public bool Deep { get; set; } = true;

    /// <summary>Ask the network over UPnP and Bonjour who's there.</summary>
    public bool Discovery { get; set; } = true;
}

public sealed record ScanProgress(string Phase, int Done, int Total);

public sealed record ScanResult(ScanRange Range, List<Device> Devices, TimeSpan Elapsed, bool Cancelled);

/// <summary>
/// One scan of a range: a ping sweep, then the ARP table (which also catches devices that ignore ping), then for every
/// device that answered: its open ports, DNS / NetBIOS / Bonjour names, SNMP description, web page title and UPnP
/// description, and finally a guess of what it is.
/// </summary>
public static class Scanner
{
    public static async Task<ScanResult> RunAsync(ScanRange range, ScanOptions opt, IProgress<ScanProgress>? progress, Action<Device>? update, CancellationToken ct)
    {
        var clock = Stopwatch.StartNew();
        var now = DateTime.Now;
        var devices = new ConcurrentDictionary<string, Device>();
        var targets = range.Addresses().ToList();
        var cancelled = false;

        Device Get(string ip) => devices.GetOrAdd(ip, k => new Device { Ip = k, FirstSeen = now, LastSeen = now, Online = true });

        try
        {
            // UPnP and Bonjour listen for a few seconds while the sweep runs.
            var ssdp = opt.Discovery ? Discovery.SsdpAsync(range.LocalIp, 3000, ct) : Task.FromResult(new Dictionary<string, Announced>());
            var mdns = opt.Discovery ? Discovery.MdnsAsync(range.LocalIp, 3200, ct) : Task.FromResult(new Dictionary<string, Announced>());

            // 1. Ping sweep
            var pinged = new ConcurrentDictionary<string, (long Ms, int Ttl)>();
            var done = 0;
            using (var gate = new SemaphoreSlim(opt.Parallel))
            {
                await Task.WhenAll(targets.Select(async ip =>
                {
                    await gate.WaitAsync(ct).ConfigureAwait(false);
                    try
                    {
                        var (ok, ms, ttl) = await Probes.PingAsync(ip, opt.PingTimeoutMs, ct).ConfigureAwait(false);
                        if (ok) pinged[ip.ToString()] = (ms, ttl);
                    }
                    finally
                    {
                        gate.Release();
                        var n = Interlocked.Increment(ref done);
                        if (n % 8 == 0 || n == targets.Count) progress?.Report(new ScanProgress("Pinging", n, targets.Count));
                    }
                })).ConfigureAwait(false);
            }

            // 2. Who answered: ping, or ARP (firewalled PCs and phones still answer ARP), plus this PC itself.
            var arp = Neighbors();
            var pending = new List<string>();
            foreach (var ip in targets.Select(t => t.ToString()))
            {
                var hasArp = arp.TryGetValue(ip, out var n);
                if (pinged.TryGetValue(ip, out var p))
                {
                    var d = Get(ip);
                    d.LatencyMs = p.Ms;
                    d.Ttl = p.Ttl;
                    if (hasArp) d.Mac = n.Mac;
                }
                else if (hasArp && n.State == NeighborState.Reachable)
                {
                    Get(ip).Mac = n.Mac;
                }
                else if (hasArp && n.State is NeighborState.Stale or NeighborState.Delay or NeighborState.Probe)
                {
                    pending.Add(ip);   // was here a while ago: look again after the deep checks
                }
            }

            if (range.LocalIp is { } self && range.Contains(self))
            {
                var d = Get(self.ToString());
                d.IsSelf = true;
                d.Mac = range.LocalMac;
                d.LatencyMs = 0;
                d.NetBiosName = Environment.MachineName;
            }

            if (range.Gateway is { } gw && devices.TryGetValue(gw.ToString(), out var g)) g.IsGateway = true;

            foreach (var d in devices.Values) Finish(d);
            foreach (var d in devices.Values) update?.Invoke(d);

            // 3. Deep checks and the network-wide announcements
            Dictionary<string, Announced> ann = [];
            if (opt.Deep)
                await DeepAsync(devices.Values.Where(d => !d.IsSelf).ToList(), opt, progress, update, ct).ConfigureAwait(false);

            var ssdpFound = await ssdp.ConfigureAwait(false);
            var mdnsFound = await mdns.ConfigureAwait(false);

            // 4. Devices that only showed up late (an ARP entry that was refreshed, or a UPnP / Bonjour answer).
            var late = new List<Device>();
            if (pending.Count > 0)
            {
                var again = Neighbors();
                foreach (var ip in pending)
                    if (again.TryGetValue(ip, out var n) && n.State == NeighborState.Reachable && !devices.ContainsKey(ip))
                    {
                        var d = Get(ip);
                        d.Mac = n.Mac;
                        late.Add(d);
                    }
            }

            foreach (var ip in ssdpFound.Keys.Concat(mdnsFound.Keys).Distinct())
            {
                if (!IPAddress.TryParse(ip, out var a) || !range.Contains(a) || devices.ContainsKey(ip)) continue;
                var d = Get(ip);
                d.Mac = Probes.Arp(a);
                late.Add(d);
            }

            if (late.Count > 0 && opt.Deep) await DeepAsync(late, opt, null, update, ct).ConfigureAwait(false);

            foreach (var (ip, a) in ssdpFound)
                if (devices.TryGetValue(ip, out var d))
                    ApplySsdp(d, a);
            foreach (var (ip, a) in mdnsFound)
                if (devices.TryGetValue(ip, out var d) && (a.OwnAddress || ip != range.Gateway?.ToString()))
                    ApplyMdns(d, a);
            if (range.Gateway is { } gw2 && devices.TryGetValue(gw2.ToString(), out var g2)) g2.IsGateway = true;
            foreach (var d in devices.Values)
            {
                Finish(d);
                update?.Invoke(d);
            }
        }
        catch (OperationCanceledException)
        {
            cancelled = true;
        }

        progress?.Report(new ScanProgress("Done", 1, 1));
        return new ScanResult(range, devices.Values.OrderBy(d => d.IpSort).ToList(), clock.Elapsed, cancelled);
    }

    /// <summary>Ports, names, web page; NetBIOS and SNMP go to every device at once from one socket each.</summary>
    private static async Task DeepAsync(List<Device> list, ScanOptions opt, IProgress<ScanProgress>? progress, Action<Device>? update, CancellationToken ct)
    {
        if (list.Count == 0) return;
        var ips = list.Select(d => IPAddress.Parse(d.Ip)).ToList();
        var netbios = UdpSweepAsync(ips, 137, Probes.NetBiosQuery, 1800, ct);
        var snmp = UdpSweepAsync(ips, 161, id => Probes.SnmpQuery(id), 1800, ct);
        var ports = PortNames.All.Select(p => p.Port).ToArray();
        var done = 0;
        using (var gate = new SemaphoreSlim(24))
        {
            await Task.WhenAll(list.Select(async d =>
            {
                await gate.WaitAsync(ct).ConfigureAwait(false);
                try
                {
                    var ip = IPAddress.Parse(d.Ip);
                    var dns = Probes.ReverseDnsAsync(ip, 2000, ct);
                    d.Ports = await Probes.OpenPortsAsync(ip, ports, opt.PortTimeoutMs, ct).ConfigureAwait(false);
                    d.DnsName = await dns.ConfigureAwait(false);
                    foreach (var port in PortNames.Web.Where(d.Ports.Contains).Take(2))
                    {
                        var (title, server) = await Probes.WebTitleAsync(ip, port, ct).ConfigureAwait(false);
                        if (d.HttpServer.Length == 0) d.HttpServer = server;
                        if (title.Length > 0)
                        {
                            d.HttpTitle = title;
                            break;
                        }
                    }

                    Finish(d);
                    update?.Invoke(d);
                }
                finally
                {
                    gate.Release();
                    var n = Interlocked.Increment(ref done);
                    progress?.Report(new ScanProgress("Identifying devices", n, list.Count));
                }
            })).ConfigureAwait(false);
        }

        foreach (var (ip, data) in await netbios.ConfigureAwait(false))
        {
            var d = list.FirstOrDefault(x => x.Ip == ip);
            if (d is null) continue;
            var (name, group) = Probes.ParseNetBios(data);
            if (name.Length > 0) d.NetBiosName = name;
            if (group.Length > 0) d.NetBiosGroup = group;
        }

        foreach (var (ip, data) in await snmp.ConfigureAwait(false))
        {
            var d = list.FirstOrDefault(x => x.Ip == ip);
            if (d is null) continue;
            var (descr, name, device) = Probes.ParseSnmp(data);
            d.SnmpDescr = device.Length > 0 && !descr.Contains(device, StringComparison.OrdinalIgnoreCase) && descr.Length < 12 ? device : descr.Length > 0 ? descr : device;
            // The first hardware device is a printer's model on printers, but a CPU on a PC or server running SNMP.
            var computer = $"{descr} {device}".ToLowerInvariant() is var t && (t.Contains("linux") || t.Contains("windows") || t.Contains("intel") || t.Contains("amd") || t.Contains("cpu") || t.Contains("processor"));
            if (device.Length > 0 && d.Model.Length == 0 && !computer) d.Model = Trim(device, 60);
            d.SnmpName = name;
        }
    }

    /// <summary>Sends one UDP packet to each address and collects the first answer from each, for <paramref name="listenMs"/>.</summary>
    private static async Task<Dictionary<string, byte[]>> UdpSweepAsync(List<IPAddress> ips, int port, Func<ushort, byte[]> packet, int listenMs, CancellationToken ct)
    {
        var got = new Dictionary<string, byte[]>();
        try
        {
            using var u = new UdpClient(0);
            // Ignore "port unreachable" from hosts that don't speak the protocol (otherwise ReceiveAsync throws).
            if (OperatingSystem.IsWindows()) u.Client.IOControl(-1744830452 /* SIO_UDP_CONNRESET */, [0, 0, 0, 0], null);
            ushort id = 0x5000;
            foreach (var ip in ips)
            {
                var p = packet(id++);
                try { await u.SendAsync(p, new IPEndPoint(ip, port), ct).ConfigureAwait(false); }
                catch (SocketException) { }
            }

            using var stop = CancellationTokenSource.CreateLinkedTokenSource(ct);
            stop.CancelAfter(listenMs);
            while (!stop.IsCancellationRequested && got.Count < ips.Count)
            {
                try
                {
                    var r = await u.ReceiveAsync(stop.Token).ConfigureAwait(false);
                    got.TryAdd(r.RemoteEndPoint.Address.MapToIPv4().ToString(), r.Buffer);
                }
                catch (OperationCanceledException) { break; }
                catch (SocketException) { }
            }
        }
        catch (OperationCanceledException) { throw; }
        catch { }

        ct.ThrowIfCancellationRequested();
        return got;
    }

    private static void ApplySsdp(Device d, Announced a)
    {
        if (a.FriendlyName.Length > 0 && !LooksLikeId(a.FriendlyName)) d.FriendlyName = a.FriendlyName;
        if (a.Manufacturer.Length > 0) d.Manufacturer = a.Manufacturer;
        if (a.Model.Length > 0) d.Model = Trim(a.Model, 60);
        if (a.DeviceType.Length > 0) d.SsdpType = a.DeviceType;
        if (a.Server.Length > 0) d.SsdpServer = Trim(a.Server, 80);
    }

    private static void ApplyMdns(Device d, Announced a)
    {
        if (a.Host.Length > 0) d.MdnsName = a.Host;
        if (a.FriendlyName.Length > 0 && (d.FriendlyName.Length == 0 || d.FriendlyName.Equals(d.Model, StringComparison.OrdinalIgnoreCase))) d.FriendlyName = a.FriendlyName;
        if (a.Model.Length > 0 && (d.Model.Length == 0 || d.Kind == DeviceKind.Unknown)) d.Model = Trim(a.Model, 60);
        if (a.Manufacturer.Length > 0 && d.Manufacturer.Length == 0) d.Manufacturer = a.Manufacturer;
        // Only service types we know: anything else is noise (sub-types, vendor-private names).
        d.Services = a.Services.Where(s => Discovery.MdnsServices.Contains(s) && s != "_services._dns-sd._udp").OrderBy(s => s).ToList();
    }

    /// <summary>Some UPnP devices give a serial or UUID as their "friendly" name.</summary>
    private static bool LooksLikeId(string s) => s.Length > 20 && !s.Contains(' ') || Guid.TryParse(s, out _);

    private static string Trim(string s, int max) => s.Length <= max ? s : s[..(max - 1)] + "…";

    /// <summary>Fills in the maker and the guess, after each new piece of information.</summary>
    public static void Finish(Device d)
    {
        if (d.Vendor.Length == 0 && d.Mac.Length == 12) d.Vendor = d.RandomMac ? "" : Vendors.Lookup(d.Mac);
        Classifier.Classify(d);
    }

    // ---------- the neighbour (ARP) table, with each entry's state ----------

    public enum NeighborState
    {
        Unreachable = 0,
        Incomplete = 1,
        Probe = 2,
        Delay = 3,
        Stale = 4,
        Reachable = 5,
        Permanent = 6,
    }

    [DllImport("iphlpapi.dll")]
    private static extern int GetIpNetTable2(ushort family, out IntPtr table);

    [DllImport("iphlpapi.dll")]
    private static extern void FreeMibTable(IntPtr memory);

    /// <summary>IPv4 address → MAC and state for every entry Windows has (MIB_IPNET_ROW2 is 88 bytes).</summary>
    public static Dictionary<string, (string Mac, NeighborState State)> Neighbors()
    {
        var result = new Dictionary<string, (string, NeighborState)>();
        if (!OperatingSystem.IsWindows()) return result;
        try
        {
            if (GetIpNetTable2(2 /* AF_INET */, out var table) != 0) return Fallback();
            try
            {
                var count = Marshal.ReadInt32(table);
                for (var i = 0; i < count; i++)
                {
                    var row = table + 8 + i * 88;
                    var family = Marshal.ReadInt16(row);
                    if (family != 2) continue;
                    var addr = new byte[4];
                    Marshal.Copy(row + 4, addr, 0, 4);
                    var len = Marshal.ReadInt32(row + 72);
                    if (len != 6) continue;
                    var mac = new byte[6];
                    Marshal.Copy(row + 40, mac, 0, 6);
                    if ((mac[0] & 1) == 1 || mac.All(b => b == 0)) continue;
                    var state = (NeighborState)Marshal.ReadInt32(row + 76);
                    var ip = new IPAddress(addr).ToString();
                    // An address can appear once per adapter: keep the liveliest.
                    if (!result.TryGetValue(ip, out var had) || state > had.Item2) result[ip] = (Convert.ToHexString(mac), state);
                }
            }
            finally
            {
                FreeMibTable(table);
            }
        }
        catch
        {
            return Fallback();
        }

        return result;

        // Older API without states: treat every entry as reachable.
        Dictionary<string, (string, NeighborState)> Fallback() => Probes.ArpTable().ToDictionary(k => k.Key, k => (k.Value, NeighborState.Reachable));
    }
}
