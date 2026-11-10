using System.IO.Compression;
using System.Text;

namespace pxdNetworkScanner.Core;

/// <summary>Who made a network card, from the first half of its MAC address (IEEE registry, built into the app).</summary>
public static class Vendors
{
    private static readonly Lazy<Dictionary<string, string>> Table = new(Load);

    // A few blocks whose registered name doesn't say what people know them as.
    private static readonly Dictionary<string, string> Better = new()
    {
        ["080027"] = "VirtualBox", ["525400"] = "QEMU / KVM", ["00155D"] = "Microsoft Hyper-V", ["00163E"] = "Xen",
        ["000C29"] = "VMware", ["005056"] = "VMware", ["000569"] = "VMware", ["001C14"] = "VMware", ["BC2411"] = "Proxmox",
    };

    private static Dictionary<string, string> Load()
    {
        var d = new Dictionary<string, string>(60_000);
        try
        {
            using var s = typeof(Vendors).Assembly.GetManifestResourceStream("oui.tsv.gz");
            if (s is null) return d;
            using var gz = new GZipStream(s, CompressionMode.Decompress);
            using var r = new StreamReader(gz, Encoding.UTF8);
            while (r.ReadLine() is { } line)
            {
                var tab = line.IndexOf('\t');
                if (tab > 0) d[line[..tab]] = Tidy(line[(tab + 1)..]);
            }
        }
        catch
        {
        }

        return d;
    }

    public static int Count => Table.Value.Count;

    /// <summary>"Nintendo Co.,Ltd" → "Nintendo", "Quectel Wireless Solutions Co.,Ltd." → "Quectel Wireless Solutions".</summary>
    public static string Tidy(string name)
    {
        var s = name.Trim();
        var comma = s.IndexOf(',');
        if (comma > 3) s = s[..comma];
        for (var i = 0; i < 3; i++)
            s = System.Text.RegularExpressions.Regex.Replace(s, @"\s+(Co\.?|Ltd\.?|Inc\.?|Corp\.?|Corporation|Limited|LLC|GmbH|S\.?A\.?|AB|AG|B\.?V\.?|Pte\.?|Pty\.?)$", "", System.Text.RegularExpressions.RegexOptions.IgnoreCase).Trim(' ', '.', ',');
        return s.Length > 0 ? s : name.Trim();
    }

    /// <summary>The maker for a MAC address (12 hex digits), "" when unknown or random.</summary>
    public static string Lookup(string mac)
    {
        if (mac.Length < 6) return "";
        mac = mac.ToUpperInvariant();
        if (Better.TryGetValue(mac[..6], out var b)) return b;
        var t = Table.Value;
        // Small blocks (MA-S /36, MA-M /28) first, then the usual /24.
        if (mac.Length >= 9 && t.TryGetValue(mac[..9], out var v)) return v;
        if (mac.Length >= 7 && t.TryGetValue(mac[..7], out v)) return v;
        return t.TryGetValue(mac[..6], out v) ? v : "";
    }
}
