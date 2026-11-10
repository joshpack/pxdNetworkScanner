using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace pxdNetworkScanner.Core;

/// <summary>What a device said about itself over UPnP (SSDP) or Bonjour (mDNS).</summary>
public sealed class Announced
{
    public string FriendlyName = "";
    public string Manufacturer = "";
    public string Model = "";
    public string DeviceType = "";
    public string Server = "";
    public string Host = "";
    public readonly HashSet<string> Services = new(StringComparer.OrdinalIgnoreCase);
    public readonly Dictionary<string, string> Txt = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>At least one answer named this address in an A record (so it isn't just a router repeating others).</summary>
    public bool OwnAddress;

    /// <summary>Adds what one more answer said.</summary>
    public void Absorb(Announced o)
    {
        foreach (var s in o.Services) Services.Add(s);
        foreach (var (k, v) in o.Txt) Txt.TryAdd(k, v);
        if (o.FriendlyName.Length > 0 && (FriendlyName.Length == 0 || o.Txt.ContainsKey("fn"))) FriendlyName = o.FriendlyName;
        if (Model.Length == 0) Model = o.Model;
        if (Manufacturer.Length == 0) Manufacturer = o.Manufacturer;
        if (Host.Length == 0) Host = o.Host;
    }
}

/// <summary>
/// Asks the whole network at once who's there: UPnP (TVs, routers, media players, printers, consoles) and Bonjour /
/// mDNS (Apple devices, printers, Chromecasts, smart-home gear). Both only listen for a few seconds.
/// </summary>
public static class Discovery
{
    // ---------- SSDP / UPnP ----------

    public static async Task<Dictionary<string, Announced>> SsdpAsync(IPAddress? local, int listenMs, CancellationToken ct)
    {
        var found = new Dictionary<string, (Announced A, string Location)>();
        try
        {
            using var u = new UdpClient(new IPEndPoint(local ?? IPAddress.Any, 0));
            u.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastTimeToLive, 2);
            var target = new IPEndPoint(IPAddress.Parse("239.255.255.250"), 1900);
            foreach (var st in new[] { "ssdp:all", "upnp:rootdevice" })
            {
                var msg = Encoding.ASCII.GetBytes($"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: {st}\r\nUSER-AGENT: Windows/10 UPnP/1.1 pxdNetworkScanner/1.0\r\n\r\n");
                await u.SendAsync(msg, target, ct).ConfigureAwait(false);
            }

            using var stop = CancellationTokenSource.CreateLinkedTokenSource(ct);
            stop.CancelAfter(listenMs);
            while (!stop.IsCancellationRequested)
            {
                UdpReceiveResult r;
                try { r = await u.ReceiveAsync(stop.Token).ConfigureAwait(false); }
                catch (OperationCanceledException) { break; }
                catch (SocketException) { continue; }
                var ip = r.RemoteEndPoint.Address.MapToIPv4().ToString();
                var headers = ParseHeaders(Encoding.UTF8.GetString(r.Buffer));
                if (!found.TryGetValue(ip, out var f)) found[ip] = f = (new Announced(), "");
                if (headers.TryGetValue("SERVER", out var server) && f.A.Server.Length == 0) f.A.Server = Probes.Clean(server);
                if (headers.TryGetValue("ST", out var stv) && stv.StartsWith("urn:", StringComparison.OrdinalIgnoreCase)) f.A.Services.Add(Short(stv));
                // Fetch the description from the device itself only (never a URL pointing somewhere else).
                if (headers.TryGetValue("LOCATION", out var loc) && Uri.TryCreate(loc, UriKind.Absolute, out var uri) && uri.Host == ip
                    && (f.Location.Length == 0 || headers.GetValueOrDefault("ST", "").Contains("rootdevice")))
                    found[ip] = (f.A, loc);
            }
        }
        catch (OperationCanceledException) { throw; }
        catch { }

        ct.ThrowIfCancellationRequested();
        await Task.WhenAll(found.Where(f => f.Value.Location.Length > 0).Select(f => DescribeAsync(f.Value.A, f.Value.Location, ct))).ConfigureAwait(false);
        return found.ToDictionary(f => f.Key, f => f.Value.A);
    }

    private static readonly HttpClient Http = new(new SocketsHttpHandler { ConnectTimeout = TimeSpan.FromSeconds(2), UseProxy = false, AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(3) };

    /// <summary>Reads a UPnP device description: its friendly name, maker, model and device type.</summary>
    private static async Task DescribeAsync(Announced a, string location, CancellationToken ct)
    {
        try
        {
            var xml = await Http.GetStringAsync(location, ct).ConfigureAwait(false);
            if (xml.Length > 512_000) return;
            ApplyDescription(a, xml);
        }
        catch
        {
        }
    }

    public static void ApplyDescription(Announced a, string xml)
    {
        var doc = XDocument.Parse(xml, LoadOptions.None);
        var dev = doc.Descendants().FirstOrDefault(e => e.Name.LocalName == "device");
        if (dev is null) return;
        string Get(string n) => Probes.Clean(dev.Elements().FirstOrDefault(e => e.Name.LocalName == n)?.Value ?? "");
        a.FriendlyName = Get("friendlyName");
        a.Manufacturer = Get("manufacturer");
        var model = Get("modelName");
        var number = Get("modelNumber");
        if (number.Length > 0 && !model.Contains(number, StringComparison.OrdinalIgnoreCase) && !number.Contains(model, StringComparison.OrdinalIgnoreCase) && number.Length < 24 && !Regex.IsMatch(number, @"^[\d.]+$")) model = (model + " " + number).Trim();
        a.Model = model;
        a.DeviceType = Short(Get("deviceType"));
    }

    /// <summary>"urn:schemas-upnp-org:device:MediaRenderer:1" → "MediaRenderer".</summary>
    private static string Short(string urn)
    {
        var p = urn.Split(':');
        return p.Length >= 4 ? p[^2] : urn;
    }

    private static Dictionary<string, string> ParseHeaders(string text)
    {
        var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in text.Split("\r\n").Skip(1))
        {
            var c = line.IndexOf(':');
            if (c > 0) d.TryAdd(line[..c].Trim(), line[(c + 1)..].Trim());
        }

        return d;
    }

    // ---------- mDNS / Bonjour ----------

    public static readonly string[] MdnsServices =
    [
        "_services._dns-sd._udp", "_device-info._tcp", "_workstation._tcp", "_companion-link._tcp", "_rdlink._tcp", "_smb._tcp", "_afpovertcp._tcp",
        "_ipp._tcp", "_ipps._tcp", "_printer._tcp", "_pdl-datastream._tcp", "_uscan._tcp", "_scanner._tcp", "_airplay._tcp", "_raop._tcp",
        "_googlecast._tcp", "_spotify-connect._tcp", "_sonos._tcp", "_amzn-wplay._tcp", "_hap._tcp", "_homekit._tcp", "_matter._tcp", "_hue._tcp",
        "_esphomelib._tcp", "_home-assistant._tcp", "_apple-mobdev2._tcp", "_ssh._tcp", "_sftp-ssh._tcp", "_http._tcp", "_androidtvremote2._tcp",
        "_nvstream._tcp", "_daap._tcp", "_touch-able._tcp", "_rfb._tcp", "_adisk._tcp", "_sleep-proxy._udp", "_meshcop._udp", "_trel._udp",
    ];

    public static byte[] MdnsQuery()
    {
        var q = new List<byte> { 0, 0, 0, 0, (byte)(MdnsServices.Length >> 8), (byte)MdnsServices.Length, 0, 0, 0, 0, 0, 0 };
        foreach (var s in MdnsServices)
        {
            foreach (var label in (s + ".local").Split('.'))
            {
                q.Add((byte)label.Length);
                q.AddRange(Encoding.ASCII.GetBytes(label));
            }

            q.Add(0);
            q.AddRange([0, 12, 0x80, 1]);   // PTR, class IN with the "unicast answer please" bit
        }

        return q.ToArray();
    }

    public static async Task<Dictionary<string, Announced>> MdnsAsync(IPAddress? local, int listenMs, CancellationToken ct)
    {
        var found = new Dictionary<string, Announced>();
                var sockets = new List<UdpClient>();
        try
        {
            // One socket on a random port (devices answer it directly), one on 5353 for devices that only answer to the group.
            var uni = new UdpClient(new IPEndPoint(local ?? IPAddress.Any, 0));
            sockets.Add(uni);
            try
            {
                var multi = new UdpClient { ExclusiveAddressUse = false };
                multi.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                multi.Client.Bind(new IPEndPoint(IPAddress.Any, 5353));
                if (local is not null) multi.JoinMulticastGroup(IPAddress.Parse("224.0.0.251"), local);
                else multi.JoinMulticastGroup(IPAddress.Parse("224.0.0.251"));
                sockets.Add(multi);
            }
            catch
            {
            }

            var query = MdnsQuery();
            var group = new IPEndPoint(IPAddress.Parse("224.0.0.251"), 5353);
            await uni.SendAsync(query, group, ct).ConfigureAwait(false);

            using var stop = CancellationTokenSource.CreateLinkedTokenSource(ct);
            stop.CancelAfter(listenMs);
            _ = Task.Delay(700, stop.Token).ContinueWith(_ => { try { uni.Send(query, query.Length, group); } catch { } }, TaskScheduler.Default);
            var receivers = sockets.Select(async s =>
            {
                while (!stop.IsCancellationRequested)
                {
                    UdpReceiveResult r;
                    try { r = await s.ReceiveAsync(stop.Token).ConfigureAwait(false); }
                    catch (OperationCanceledException) { break; }
                    catch (SocketException) { continue; }
                    var ip = r.RemoteEndPoint.Address.MapToIPv4().ToString();
                    // Routers that repeat Bonjour between networks (UniFi "mDNS reflector") send other devices' answers
                    // from their own address, so an answer belongs to the address in its A record when it has one.
                    var one = new Announced();
                    var addresses = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    ParseMdns(r.Buffer, one, addresses);
                    var owner = addresses.Values.FirstOrDefault() ?? ip;
                    lock (found)
                    {
                        if (!found.TryGetValue(owner, out var a)) found[owner] = a = new Announced();
                        a.Absorb(one);
                        if (addresses.Count > 0) a.OwnAddress = true;
                    }
                }
            }).ToList();
            await Task.WhenAll(receivers).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { throw; }
        catch { }
        finally
        {
            foreach (var s in sockets) s.Dispose();
        }

        ct.ThrowIfCancellationRequested();
        // Our own query echoes back; drop senders that said nothing.
        return found.Where(f => f.Value.Services.Count > 0 || f.Value.Host.Length > 0).ToDictionary(f => f.Key, f => f.Value);
    }

    /// <summary>Reads one mDNS answer packet into what its sender said about itself.</summary>
    public static void ParseMdns(byte[] d, Announced a, Dictionary<string, string>? hostIps = null)
    {
        try
        {
            if (d.Length < 12 || (d[2] & 0x80) == 0) return;   // only responses
            var qd = d[4] << 8 | d[5];
            var rr = (d[6] << 8 | d[7]) + (d[8] << 8 | d[9]) + (d[10] << 8 | d[11]);
            var i = 12;
            for (var n = 0; n < qd; n++)
            {
                ReadName(d, ref i);
                i += 4;
            }

            for (var n = 0; n < rr && i < d.Length; n++)
            {
                var name = ReadName(d, ref i);
                var type = d[i] << 8 | d[i + 1];
                var len = d[i + 8] << 8 | d[i + 9];
                var start = i + 10;
                var end = start + len;
                if (end > d.Length) return;
                switch (type)
                {
                    case 12:   // PTR: service type → instance
                    {
                        var p = start;
                        var target = ReadName(d, ref p);
                        if (name.StartsWith("_services._dns-sd", StringComparison.OrdinalIgnoreCase))
                        {
                            // the list of service types it offers
                            if (ServiceOf(target) is { Length: > 0 } offered) a.Services.Add(offered);
                            break;
                        }

                        var svc = ServiceOf(name);
                        if (svc.Length > 0) a.Services.Add(svc);
                        var inst = InstanceOf(target);
                        if (inst.Length > 0 && svc is "_googlecast._tcp" or "_airplay._tcp" or "_raop._tcp" or "_ipp._tcp" or "_printer._tcp" or "_sonos._tcp" or "_hap._tcp" or "_amzn-wplay._tcp" or "_companion-link._tcp"
                            && a.FriendlyName.Length == 0)
                            a.FriendlyName = svc == "_raop._tcp" && inst.Contains('@') ? inst[(inst.IndexOf('@') + 1)..] : inst;
                        break;
                    }
                    case 33:   // SRV: instance → host name
                    {
                        var p = start + 6;
                        var host = ReadName(d, ref p);
                        if (host.Length > 0 && a.Host.Length == 0) a.Host = host.TrimEnd('.');
                        var svc = ServiceOf(name);
                        if (svc.Length > 0) a.Services.Add(svc);
                        break;
                    }
                    case 16:   // TXT: key=value pairs (model, friendly name, printer type)
                    {
                        var p = start;
                        while (p < end)
                        {
                            int l = d[p++];
                            if (l == 0 || p + l > end) break;
                            var kv = Encoding.UTF8.GetString(d, p, l);
                            p += l;
                            var eq = kv.IndexOf('=');
                            if (eq > 0) a.Txt.TryAdd(kv[..eq], kv[(eq + 1)..]);
                        }

                        break;
                    }
                    case 1 when len == 4:   // A
                    {
                        var ip = new IPAddress(d[start..end]).ToString();
                        if (hostIps is not null) hostIps[name.TrimEnd('.')] = ip;
                        if (a.Host.Length == 0 && name.EndsWith(".local", StringComparison.OrdinalIgnoreCase)) a.Host = name.TrimEnd('.');
                        break;
                    }
                }

                i = end;
            }
        }
        catch
        {
        }

        // What the TXT records give away about the model.
        string T(string k) => a.Txt.TryGetValue(k, out var v) ? Probes.Clean(v) : "";
        if (T("fn") is { Length: > 0 } fn) a.FriendlyName = fn;   // Google Cast's own "friendly name"
        foreach (var k in new[] { "md", "ty", "usb_MDL", "product", "am", "model", "rpMd" })
        {
            var v = T(k).Trim('(', ')');
            if (v.Length > 0 && a.Model.Length == 0) a.Model = v;
        }

        if (a.Manufacturer.Length == 0 && T("usb_MFG") is { Length: > 0 } mfg) a.Manufacturer = mfg;
    }

    /// <summary>"Living Room._googlecast._tcp.local" → "_googlecast._tcp".</summary>
    public static string ServiceOf(string name)
    {
        var m = Regex.Match(name, @"(_[A-Za-z0-9-]+\._(tcp|udp))\.local\.?$", RegexOptions.IgnoreCase);
        return m.Success ? m.Groups[1].Value.ToLowerInvariant() : "";
    }

    /// <summary>"Living Room._googlecast._tcp.local" → "Living Room".</summary>
    public static string InstanceOf(string name)
    {
        var m = Regex.Match(name, @"^(.+?)\._[A-Za-z0-9-]+\._(tcp|udp)\.local\.?$", RegexOptions.IgnoreCase);
        return m.Success ? m.Groups[1].Value.Replace("\\032", " ") : "";
    }

    private static string ReadName(byte[] d, ref int i)
    {
        var parts = new List<string>();
        var jumped = false;
        var p = i;
        for (var guard = 0; guard < 64 && p < d.Length; guard++)
        {
            int len = d[p];
            if (len == 0)
            {
                p++;
                break;
            }

            if ((len & 0xC0) == 0xC0)
            {
                var ptr = (len & 0x3F) << 8 | d[p + 1];
                if (!jumped) i = p + 2;
                jumped = true;
                p = ptr;
                continue;
            }

            parts.Add(Encoding.UTF8.GetString(d, p + 1, len));
            p += len + 1;
        }

        if (!jumped) i = p;
        return string.Join(".", parts);
    }
}
