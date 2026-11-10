using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

namespace pxdNetworkScanner.Core;

/// <summary>The TCP ports the scan knocks on, and what each one usually means.</summary>
public static class PortNames
{
    public static readonly (int Port, string Name)[] All =
    [
        (21, "FTP"), (22, "SSH"), (23, "Telnet"), (53, "DNS"), (80, "Web"), (135, "Windows RPC"), (139, "NetBIOS"), (443, "Web (HTTPS)"),
        (445, "File sharing (SMB)"), (515, "LPD printing"), (548, "Apple file sharing"), (554, "Video stream (RTSP)"), (631, "IPP printing"),
        (1400, "Sonos"), (1883, "MQTT"), (3389, "Remote Desktop"), (5000, "Web (5000)"), (5001, "Web (5001)"), (5357, "Windows device discovery"),
        (5900, "VNC screen sharing"), (7000, "AirPlay"), (8006, "Proxmox"), (8008, "Google Cast / web"), (8009, "Google Cast"), (8060, "Roku"),
        (8080, "Web (8080)"), (8123, "Home Assistant"), (8443, "Web (8443)"), (9100, "Raw printing"), (32400, "Plex"), (62078, "iPhone / iPad sync"),
    ];

    private static readonly Dictionary<int, string> Map = All.ToDictionary(p => p.Port, p => p.Name);

    public static string Name(int port) => Map.TryGetValue(port, out var n) ? n : "";

    public static readonly int[] Web = [80, 443, 5000, 5001, 8080, 8443, 8006, 8123];

    public static bool IsHttps(int port) => port is 443 or 8443 or 5001 or 8006;
}

/// <summary>The small network checks one device at a time: ping, the ARP table, TCP ports, names, SNMP and web page titles.</summary>
public static class Probes
{
    // ---------- Ping ----------

    public static async Task<(bool Ok, long Ms, int Ttl)> PingAsync(IPAddress ip, int timeoutMs, CancellationToken ct)
    {
        using var p = new Ping();
        for (var attempt = 0; attempt < 2; attempt++)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                var r = await p.SendPingAsync(ip, TimeSpan.FromMilliseconds(timeoutMs), new byte[16], new PingOptions(128, true), ct).ConfigureAwait(false);
                if (r.Status == IPStatus.Success) return (true, r.RoundtripTime, r.Options?.Ttl ?? 0);
            }
            catch (OperationCanceledException) { throw; }
            catch { }
        }

        return (false, -1, 0);
    }

    // ---------- ARP table: hosts that answered ARP even when they ignore ping ----------

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_IPNETROW
    {
        public int dwIndex;
        public int dwPhysAddrLen;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)] public byte[] bPhysAddr;
        public uint dwAddr;
        public int dwType;
    }

    [DllImport("iphlpapi.dll")]
    private static extern int GetIpNetTable(IntPtr pIpNetTable, ref int pdwSize, bool bOrder);

    [DllImport("iphlpapi.dll")]
    private static extern int SendARP(uint destIp, uint srcIp, byte[] macAddr, ref int physAddrLen);

    /// <summary>IP → MAC (12 hex digits) for every resolved entry in Windows' ARP table.</summary>
    public static Dictionary<string, string> ArpTable()
    {
        var result = new Dictionary<string, string>();
        if (!OperatingSystem.IsWindows()) return result;
        var size = 0;
        GetIpNetTable(IntPtr.Zero, ref size, false);
        if (size <= 0) return result;
        var buf = Marshal.AllocHGlobal(size);
        try
        {
            if (GetIpNetTable(buf, ref size, true) != 0) return result;
            var count = Marshal.ReadInt32(buf);
            var rowSize = Marshal.SizeOf<MIB_IPNETROW>();
            for (var i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<MIB_IPNETROW>(buf + 4 + i * rowSize);
                if (row.dwType is not (3 or 4) || row.dwPhysAddrLen != 6) continue;   // 3 = dynamic, 4 = static
                var mac = Convert.ToHexString(row.bPhysAddr, 0, 6);
                if (mac is "000000000000" or "FFFFFFFFFFFF" || (row.bPhysAddr[0] & 1) == 1) continue;   // multicast entries
                result[new IPAddress(row.dwAddr).ToString()] = mac;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buf);
        }

        return result;
    }

    /// <summary>Asks for one address's MAC (blocks up to ~1 s for an address nobody has). Same network only.</summary>
    public static string Arp(IPAddress ip)
    {
        if (!OperatingSystem.IsWindows()) return "";
        try
        {
            var mac = new byte[6];
            var len = mac.Length;
            var dest = BitConverter.ToUInt32(ip.GetAddressBytes(), 0);
            return SendARP(dest, 0, mac, ref len) == 0 && len == 6 ? Convert.ToHexString(mac) : "";
        }
        catch
        {
            return "";
        }
    }

    // ---------- TCP ports ----------

    public static async Task<List<int>> OpenPortsAsync(IPAddress ip, IEnumerable<int> ports, int timeoutMs, CancellationToken ct)
    {
        var tasks = ports.Select(async port =>
        {
            using var c = new TcpClient(AddressFamily.InterNetwork);
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeoutMs);
            try
            {
                await c.ConnectAsync(ip, port, cts.Token).ConfigureAwait(false);
                return c.Connected ? port : -1;
            }
            catch
            {
                return -1;
            }
        }).ToList();
        var done = await Task.WhenAll(tasks).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested();
        return done.Where(p => p > 0).OrderBy(p => p).ToList();
    }

    // ---------- Reverse DNS ----------

    public static async Task<string> ReverseDnsAsync(IPAddress ip, int timeoutMs, CancellationToken ct)
    {
        try
        {
            var t = Dns.GetHostEntryAsync(ip);
            var done = await Task.WhenAny(t, Task.Delay(timeoutMs, ct)).ConfigureAwait(false);
            if (done != t || !t.IsCompletedSuccessfully) return "";
            var name = t.Result.HostName;
            return name == ip.ToString() ? "" : name.TrimEnd('.');
        }
        catch
        {
            return "";
        }
    }

    // ---------- NetBIOS name (Windows PCs, Samba, many NAS boxes) ----------

    /// <summary>A NetBIOS node-status query: asks "who are you" on UDP 137.</summary>
    public static byte[] NetBiosQuery(ushort id)
    {
        var q = new List<byte> { (byte)(id >> 8), (byte)id, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0x20 };
        // "*" padded with NULs, each half-byte encoded as a letter from 'A'
        var name = new byte[16];
        name[0] = (byte)'*';
        foreach (var b in name)
        {
            q.Add((byte)('A' + (b >> 4)));
            q.Add((byte)('A' + (b & 0xF)));
        }

        q.AddRange([0, 0, 0x21, 0, 1]);
        return q.ToArray();
    }

    /// <summary>Reads a node-status answer: the computer name and its workgroup or domain.</summary>
    public static (string Name, string Group) ParseNetBios(byte[] d)
    {
        try
        {
            var i = 12;
            while (i < d.Length && d[i] != 0) i += d[i] + 1;
            i += 1 + 2 + 2 + 4 + 2;   // end of name, type, class, TTL, data length
            int count = d[i++];
            string name = "", group = "";
            for (var n = 0; n < count && i + 18 <= d.Length; n++, i += 18)
            {
                var text = Encoding.ASCII.GetString(d, i, 15).TrimEnd(' ', '\0');
                var suffix = d[i + 15];
                var isGroup = (d[i + 16] & 0x80) != 0;
                if (suffix == 0 && !isGroup && name.Length == 0) name = text;
                else if (suffix == 0 && isGroup && group.Length == 0) group = text;
            }

            return (name, group);
        }
        catch
        {
            return ("", "");
        }
    }

    // ---------- SNMP (printers and network gear describe themselves) ----------

    private static readonly byte[] OidSysDescr = [0x2B, 6, 1, 2, 1, 1, 1, 0];
    private static readonly byte[] OidSysName = [0x2B, 6, 1, 2, 1, 1, 5, 0];
    private static readonly byte[] OidHrDevice = [0x2B, 6, 1, 2, 1, 0x19, 3, 2, 1, 3, 1];

    /// <summary>An SNMP v2c GET for sysDescr, sysName and the first host-resources device (a printer's model), community "public".</summary>
    public static byte[] SnmpQuery(int requestId)
    {
        static byte[] Tlv(byte tag, params byte[][] parts)
        {
            var body = parts.SelectMany(p => p).ToArray();
            var len = body.Length < 128 ? [(byte)body.Length] : new[] { (byte)0x81, (byte)body.Length };
            return [tag, .. len, .. body];
        }

        byte[] Bind(byte[] oid) => Tlv(0x30, Tlv(0x06, oid), [0x05, 0x00]);
        var id = BitConverter.GetBytes(requestId & 0x7FFFFFFF).Reverse().ToArray();
        var pdu = Tlv(0xA0, Tlv(0x02, id), Tlv(0x02, [0]), Tlv(0x02, [0]), Tlv(0x30, Bind(OidSysDescr), Bind(OidSysName), Bind(OidHrDevice)));
        return Tlv(0x30, Tlv(0x02, [1]), Tlv(0x04, "public"u8.ToArray()), pdu);
    }

    /// <summary>Reads the text values out of an SNMP answer.</summary>
    public static (string Descr, string Name, string Device) ParseSnmp(byte[] d)
    {
        string descr = "", name = "", device = "";
        try
        {
            var binds = new List<(byte[] Oid, byte[] Value, byte Tag)>();
            void Walk(int start, int end)
            {
                var i = start;
                while (i < end)
                {
                    var tag = d[i++];
                    int len = d[i++];
                    if ((len & 0x80) != 0)
                    {
                        var n = len & 0x7F;
                        len = 0;
                        for (var k = 0; k < n; k++) len = (len << 8) | d[i++];
                    }

                    if (i + len > end) return;
                    if (tag == 0x30 && len > 2 && d[i] == 0x06)
                    {
                        // a varbind: OID then value
                        int olen = d[i + 1];
                        var oid = d[(i + 2)..(i + 2 + olen)];
                        var v = i + 2 + olen;
                        if (v + 1 < i + len)
                        {
                            var vtag = d[v];
                            int vlen = d[v + 1];
                            var vs = v + 2;
                            if ((vlen & 0x80) != 0)
                            {
                                var n = vlen & 0x7F;
                                vlen = 0;
                                for (var k = 0; k < n; k++) vlen = (vlen << 8) | d[vs++];
                            }

                            if (vs + vlen <= d.Length) binds.Add((oid, d[vs..(vs + vlen)], vtag));
                        }
                    }
                    else if (tag is 0x30 or 0xA2 or 0xA0)
                    {
                        Walk(i, i + len);
                    }

                    i += len;
                }
            }

            Walk(0, d.Length);
            foreach (var (oid, value, tag) in binds)
            {
                if (tag != 0x04) continue;
                var text = Clean(Encoding.UTF8.GetString(value));
                if (oid.SequenceEqual(OidSysDescr)) descr = text;
                else if (oid.SequenceEqual(OidSysName)) name = text;
                else if (oid.SequenceEqual(OidHrDevice)) device = text;
            }
        }
        catch
        {
        }

        return (descr, name, device);
    }

    // ---------- Web page title ----------

    private static readonly HttpClient Http = MakeHttp();

    private static HttpClient MakeHttp()
    {
        var h = new SocketsHttpHandler
        {
            // LAN devices (printers, routers, NAS) nearly all use self-signed certificates; we only read the page title.
            SslOptions = { RemoteCertificateValidationCallback = (_, _, _, _) => true },
            AllowAutoRedirect = true,
            MaxAutomaticRedirections = 3,
            ConnectTimeout = TimeSpan.FromSeconds(2),
            UseProxy = false,
            UseCookies = false,
        };
        var c = new HttpClient(h) { Timeout = TimeSpan.FromSeconds(4) };
        c.DefaultRequestHeaders.UserAgent.ParseAdd("pxdNetworkScanner/1.0");
        return c;
    }

    public static async Task<(string Title, string Server)> WebTitleAsync(IPAddress ip, int port, CancellationToken ct)
    {
        var url = $"{(PortNames.IsHttps(port) ? "https" : "http")}://{ip}{(port is 80 or 443 ? "" : ":" + port)}/";
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(4000);
            using var res = await Http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, cts.Token).ConfigureAwait(false);
            var server = res.Headers.Server.ToString();
            // Stay on the device: a redirect to some other host isn't this device's page.
            if (res.RequestMessage?.RequestUri is { } final && final.Host != ip.ToString()) return ("", Clean(server));
            await using var s = await res.Content.ReadAsStreamAsync(cts.Token).ConfigureAwait(false);
            var buf = new byte[65536];
            var total = 0;
            int n;
            while (total < buf.Length && (n = await s.ReadAsync(buf.AsMemory(total), cts.Token).ConfigureAwait(false)) > 0) total += n;
            var html = Encoding.UTF8.GetString(buf, 0, total);
            var m = Regex.Match(html, @"<title[^>]*>\s*(.*?)\s*</title>", RegexOptions.IgnoreCase | RegexOptions.Singleline);
            var title = m.Success ? Clean(WebUtility.HtmlDecode(m.Groups[1].Value)) : "";
            if (title.Length > 90) title = title[..89] + "…";
            return (title, Clean(server));
        }
        catch
        {
            return ("", "");
        }
    }

    // ---------- Wake-on-LAN ----------

    /// <summary>Sends the magic packet (FF×6 then the MAC ×16) to the network's broadcast address, port 9.</summary>
    public static bool Wake(string mac, IPAddress? broadcast)
    {
        if (mac.Length != 12) return false;
        try
        {
            var m = Convert.FromHexString(mac);
            var packet = new byte[102];
            for (var i = 0; i < 6; i++) packet[i] = 0xFF;
            for (var i = 0; i < 16; i++) m.CopyTo(packet, 6 + i * 6);
            using var u = new UdpClient { EnableBroadcast = true };
            u.Send(packet, packet.Length, new IPEndPoint(broadcast ?? IPAddress.Broadcast, 9));
            if (broadcast is not null && !broadcast.Equals(IPAddress.Broadcast)) u.Send(packet, packet.Length, new IPEndPoint(IPAddress.Broadcast, 9));
            return true;
        }
        catch
        {
            return false;
        }
    }

    public static string Clean(string s) => Regex.Replace(s.Replace('\0', ' '), @"\s+", " ").Trim();
}
