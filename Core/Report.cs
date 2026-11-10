using System.Net;
using System.Text;
using System.Text.Json;

namespace pxdNetworkScanner.Core;

/// <summary>The device list as CSV (for Excel), JSON, plain text or a self-contained HTML page.</summary>
public static class Report
{
    public static string For(string path, IReadOnlyList<Device> devices, string network, DateTime when) =>
        Path.GetExtension(path).ToLowerInvariant() switch
        {
            ".csv" => Csv(devices),
            ".json" => JsonText(devices, network, when),
            ".txt" => Text(devices, network, when),
            _ => Html(devices, network, when),
        };

    private static readonly string[] Columns = ["Status", "Name", "Type", "IP address", "MAC address", "Maker", "Model", "Host names", "System", "Open ports", "Web page", "Last seen"];

    private static string[] Row(Device d) =>
    [
        d.Online ? "Online" : "Offline", d.Name, d.KindText, d.Ip, Device.Pretty(d.Mac), d.Vendor,
        string.Join(" ", new[] { d.Manufacturer, d.Model }.Where(s => s.Length > 0).Distinct()), string.Join(", ", d.HostNames), d.Os,
        string.Join(" ", d.Ports), d.HttpTitle, d.LastSeen.ToString("yyyy-MM-dd HH:mm"),
    ];

    public static string Csv(IReadOnlyList<Device> devices)
    {
        static string Q(string s) => s.IndexOfAny([',', '"', '\n', '\r']) >= 0 || s.StartsWith('=') || s.StartsWith('+') || s.StartsWith('-') || s.StartsWith('@')
            ? "\"" + (s.StartsWith('=') || s.StartsWith('+') || s.StartsWith('-') || s.StartsWith('@') ? "'" : "") + s.Replace("\"", "\"\"") + "\""
            : s;
        var sb = new StringBuilder();
        sb.AppendLine(string.Join(",", Columns));
        foreach (var d in devices) sb.AppendLine(string.Join(",", Row(d).Select(Q)));
        return sb.ToString();
    }

    public static string JsonText(IReadOnlyList<Device> devices, string network, DateTime when) =>
        JsonSerializer.Serialize(new
        {
            network, scanned = when,
            devices = devices.Select(d => new
            {
                online = d.Online, name = d.Name, type = d.KindText, kind = d.Kind.ToString(), ip = d.Ip, mac = Device.Pretty(d.Mac), randomMac = d.RandomMac,
                maker = d.Vendor, manufacturer = d.Manufacturer, model = d.Model, dns = d.DnsName, netbios = d.NetBiosName, workgroup = d.NetBiosGroup,
                mdns = d.MdnsName, system = d.Os, ports = d.Ports, services = d.Services, webTitle = d.HttpTitle, webServer = d.HttpServer,
                upnp = d.SsdpType, snmp = d.SnmpDescr, latencyMs = d.LatencyMs, why = d.Why, firstSeen = d.FirstSeen, lastSeen = d.LastSeen,
            }),
        }, new JsonSerializerOptions { WriteIndented = true });

    public static string Text(IReadOnlyList<Device> devices, string network, DateTime when)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"pxd Network Scanner: {network}, {when:yyyy-MM-dd HH:mm}");
        sb.AppendLine($"{devices.Count(d => d.Online)} online, {devices.Count(d => !d.Online)} offline");
        sb.AppendLine();
        foreach (var d in devices)
        {
            sb.AppendLine(d.Details());
            sb.AppendLine();
        }

        return sb.ToString();
    }

    public static string Html(IReadOnlyList<Device> devices, string network, DateTime when)
    {
        static string E(string s) => WebUtility.HtmlEncode(s);
        var sb = new StringBuilder();
        sb.Append($$"""
            <!doctype html>
            <html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
            <title>Network scan {{E(network)}}</title>
            <style>
            body { margin: 0; padding: 24px; background: #0E1015; color: #E8EAF0; font: 14px/1.45 "Segoe UI", system-ui, sans-serif; }
            h1 { margin: 0 0 4px; font-size: 22px; } .muted { color: #8A92A6; }
            table { border-collapse: collapse; width: 100%; margin-top: 18px; }
            th, td { text-align: left; padding: 7px 10px; border-bottom: 1px solid #272C39; vertical-align: top; }
            th { color: #8A92A6; font-size: 12px; text-transform: uppercase; letter-spacing: .06em; }
            tr.off td { color: #6B7285; } .on { color: #19F58C; } .mono { font-family: Consolas, monospace; font-size: 13px; }
            </style></head><body>
            <h1>pxd Network Scanner</h1>
            <div class="muted">{{E(network)}} · {{when:yyyy-MM-dd HH:mm}} · {{devices.Count(d => d.Online)}} online, {{devices.Count(d => !d.Online)}} offline</div>
            <table><thead><tr><th></th><th>Name</th><th>Type</th><th>IP address</th><th>MAC address</th><th>Maker / model</th><th>Open ports</th><th>Last seen</th></tr></thead><tbody>

            """);
        foreach (var d in devices)
        {
            var model = string.Join(" · ", new[] { d.Vendor, string.Join(" ", new[] { d.Manufacturer, d.Model }.Where(s => s.Length > 0).Distinct()) }.Where(s => s.Length > 0).Distinct());
            sb.Append($"<tr class=\"{(d.Online ? "" : "off")}\"><td class=\"{(d.Online ? "on" : "")}\">{(d.Online ? "●" : "○")}</td><td>{E(d.Name)}<div class=\"muted\">{E(string.Join(", ", d.HostNames))}</div></td>")
                .Append($"<td>{E(d.KindText)}<div class=\"muted\">{E(string.Join("; ", d.Why))}</div></td><td class=\"mono\">{E(d.Ip)}</td><td class=\"mono\">{E(Device.Pretty(d.Mac))}</td>")
                .Append($"<td>{E(model)}</td><td class=\"mono\">{E(string.Join(" ", d.Ports))}</td><td>{d.LastSeen:yyyy-MM-dd HH:mm}</td></tr>\n");
        }

        sb.Append("</tbody></table></body></html>\n");
        return sb.ToString();
    }
}
