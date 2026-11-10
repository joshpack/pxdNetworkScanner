namespace pxdNetworkScanner.Core;

/// <summary>The short "worth a look" notes shown under the results after a scan (same rules as the PowerShell edition).</summary>
public static class Summary
{
    public enum Level
    {
        Bad,
        Warn,
        Info,
        Good,
    }

    public static List<(Level Level, string Text)> Insights(IReadOnlyList<Device> online, IReadOnlyList<Device> added, IReadOnlyList<Device> gone)
    {
        var o = new List<(Level, string)>();
        static string Label(Device d) => d.Name == d.Ip ? d.Ip : $"{d.Name} ({d.Ip})";
        static string List(IReadOnlyList<Device> ds)
        {
            var names = ds.Take(3).Select(Label).ToList();
            var more = ds.Count - names.Count;
            return string.Join(", ", names) + (more > 0 ? $" and {more} more" : "");
        }

        var telnet = online.Where(d => d.Has(23)).ToList();
        if (telnet.Count > 0) o.Add((Level.Bad, $"Telnet is open on {List(telnet)}: it sends passwords in plain text; turn it off."));
        var ftp = online.Where(d => d.Has(21)).ToList();
        if (ftp.Count > 0) o.Add((Level.Warn, $"FTP is open on {List(ftp)}: unencrypted file transfer."));
        var vnc = online.Where(d => d.Has(5900) && !d.IsSelf).ToList();
        if (vnc.Count > 0) o.Add((Level.Warn, $"Screen sharing (VNC) is open on {List(vnc)}."));
        var rdp = online.Where(d => d.Has(3389) && !d.IsSelf).ToList();
        if (rdp.Count > 0) o.Add((Level.Info, $"Remote Desktop answers on {List(rdp)}."));
        var unknown = online.Where(d => d.Kind == DeviceKind.Unknown).ToList();
        if (unknown.Count > 0) o.Add((Level.Warn, $"{unknown.Count} device{(unknown.Count == 1 ? "" : "s")} nothing could identify: {List(unknown)}."));
        if (added.Count > 0) o.Add((Level.Good, $"New since the last scan: {List(added)}."));
        if (gone.Count > 0) o.Add((Level.Warn, $"Gone since the last scan: {List(gone)}."));
        return o;
    }
}
