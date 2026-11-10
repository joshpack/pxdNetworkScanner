using System.Text.Json;

namespace pxdNetworkScanner.Core;

/// <summary>
/// Every device seen on each network, so a device that's off now still shows (as offline, with when it was last
/// seen) and keeps the name the user gave it. Saved as devices.json in the app's data folder.
/// </summary>
public sealed class DeviceStore
{
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };
    private readonly string? _file;
    private readonly object _lock = new();

    public List<Device> Items { get; } = [];

    public DeviceStore(string? file)
    {
        _file = file;
        if (file is null || !File.Exists(file)) return;
        try
        {
            if (JsonSerializer.Deserialize<List<Device>>(File.ReadAllText(file), Json) is { } list) Items.AddRange(list);
            foreach (var d in Items) d.Online = false;
        }
        catch
        {
            // a damaged file starts a fresh list rather than stopping the app
        }
    }

    /// <summary>Marks everything in <paramref name="range"/> offline until the new scan finds it again.</summary>
    public void BeginScan(ScanRange range)
    {
        lock (_lock)
            foreach (var d in Items)
                if (System.Net.IPAddress.TryParse(d.Ip, out var ip) && range.Contains(ip))
                    d.Online = false;
    }

    /// <summary>Takes one scanned device: updates the remembered one (by MAC, else by IP) or adds it. Returns the kept copy.</summary>
    public Device Merge(Device scan)
    {
        lock (_lock)
        {
            // Same MAC and IP; else the same MAC that hasn't answered yet this scan (it moved to a new IP); else an
            // IP-only record. One MAC can answer on two IPs at once (a device with two addresses): those stay two rows.
            var kept = scan.Mac.Length > 0
                ? Items.FirstOrDefault(d => d.Mac == scan.Mac && d.Ip == scan.Ip) ?? Items.FirstOrDefault(d => d.Mac == scan.Mac && !d.Online)
                  ?? Items.FirstOrDefault(d => d.Mac.Length == 0 && d.Ip == scan.Ip)
                : Items.FirstOrDefault(d => d.Ip == scan.Ip && (d.Online || d.Mac.Length == 0)) ?? Items.FirstOrDefault(d => d.Ip == scan.Ip);
            if (kept is null)
            {
                kept = new Device { FirstSeen = scan.FirstSeen };
                Items.Add(kept);
            }

            // Someone else now has this IP: the old record keeps its MAC and goes offline.
            foreach (var other in Items.Where(d => d != kept && d.Ip == scan.Ip && d.Online)) other.Online = false;
            kept.Absorb(scan);
            Scanner.Finish(kept);
            return kept;
        }
    }

    public void Forget(Device d)
    {
        lock (_lock) Items.Remove(d);
    }

    public void ForgetOffline()
    {
        lock (_lock) Items.RemoveAll(d => !d.Online);
    }

    public void Save()
    {
        if (_file is null) return;
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_file)!);
            string text;
            lock (_lock) text = JsonSerializer.Serialize(Items.OrderBy(d => d.IpSort).ToList(), Json);
            var tmp = _file + ".tmp";
            File.WriteAllText(tmp, text);
            File.Move(tmp, _file, overwrite: true);
        }
        catch
        {
        }
    }
}
