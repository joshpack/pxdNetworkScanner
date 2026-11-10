using System.Text;
using pxdStandard;

namespace pxdNetworkScanner;

/// <summary>
/// Self-test of updating before start (pxdUpdate): a made-up newer release served by a local HttpListener, installed
/// into a temp folder. The running copy and any real install are never updated.
/// </summary>
internal static class SelfTestUpdate
{
    public static async Task<List<(string Name, bool Ok, string Detail)>> RunAsync(string dir)
    {
        var results = new List<(string Name, bool Ok, string Detail)>();
        void Check(string name, bool ok, string detail = "") => results.Add((name, ok, detail));

        var app = Program.AppId;
        var root = Path.Combine(dir, "update");
        if (Directory.Exists(root))
            Directory.Delete(root, recursive: true);
        var install = Path.Combine(root, "install");
        var pkg = Path.Combine(root, "pkg", app);
        Directory.CreateDirectory(install);
        Directory.CreateDirectory(pkg);
        var exe = Path.Combine(install, app + ".exe");
        File.WriteAllText(exe, "old exe");
        File.WriteAllText(Path.Combine(install, "lib.dll"), "old lib");
        File.WriteAllText(Path.Combine(install, "keep.json"), "user file");
        File.WriteAllText(Path.Combine(pkg, app + ".exe"), "new exe");
        File.WriteAllText(Path.Combine(pkg, "lib.dll"), "new lib");
        File.WriteAllText(Path.Combine(pkg, "extra.dll"), "new file");
        var zipName = $"{app}-9.9.9-win-x64.zip";
        var zip = Path.Combine(root, zipName);
        System.IO.Compression.ZipFile.CreateFromDirectory(Path.Combine(root, "pkg"), zip);
        var hash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(zip))).ToLowerInvariant();

        var port = Random.Shared.Next(41000, 49000);
        var prefix = $"http://127.0.0.1:{port}/";
        using var listener = new System.Net.HttpListener();
        listener.Prefixes.Add(prefix);
        listener.Start();
        var hits = 0;
        var badSum = false;
        var serving = Task.Run(async () =>
        {
            while (listener.IsListening)
            {
                System.Net.HttpListenerContext ctx;
                try { ctx = await listener.GetContextAsync(); } catch { return; }
                Interlocked.Increment(ref hits);
                byte[] body = ctx.Request.Url!.AbsolutePath switch
                {
                    var p when p == $"/repos/{Program.UpdateRepo}/releases/latest" => Encoding.UTF8.GetBytes(
                        $"{{\"tag_name\":\"v9.9.9\",\"assets\":[{{\"name\":\"{app}-9.9.9-linux-x64.tar.gz\",\"browser_download_url\":\"{prefix}other\"}}," +
                        $"{{\"name\":\"{zipName}\",\"browser_download_url\":\"{prefix}zip\"}},{{\"name\":\"{zipName}.sha256\",\"browser_download_url\":\"{prefix}sum\"}}]}}"),
                    "/zip" => File.ReadAllBytes(zip),
                    "/sum" => Encoding.ASCII.GetBytes((badSum ? new string('0', 64) : hash) + "  " + zipName),
                    _ => [],
                };
                ctx.Response.StatusCode = body.Length == 0 ? 404 : 200;
                try { await ctx.Response.OutputStream.WriteAsync(body); } catch { /* client gone */ }
                ctx.Response.Close();
            }
        });

        var savedApi = Environment.GetEnvironmentVariable("PXD_UPDATE_API");
        var savedNo = Environment.GetEnvironmentVariable("PXD_NO_UPDATE");
        Environment.SetEnvironmentVariable("PXD_UPDATE_API", prefix.TrimEnd('/'));
        try
        {
            // The start-up call: never updates during a self-test, with PXD_NO_UPDATE=1, or from a dev build in bin\.
            Check("Update: BeforeStart skipped for --self-test", !pxdUpdate.BeforeStart(Program.UpdateRepo, Program.UpdateAsset, ["--self-test", dir]) && hits == 0);
            Environment.SetEnvironmentVariable("PXD_NO_UPDATE", "1");
            Check("Update: BeforeStart skipped with PXD_NO_UPDATE=1", !pxdUpdate.BeforeStart(Program.UpdateRepo, Program.UpdateAsset, []) && hits == 0);
            Environment.SetEnvironmentVariable("PXD_NO_UPDATE", savedNo);
            var here = Path.GetDirectoryName(Environment.ProcessPath) ?? "";
            if (here.Contains(@"\bin\", StringComparison.OrdinalIgnoreCase))
                Check(@"Update: BeforeStart skipped for a dev build (bin\)", !pxdUpdate.BeforeStart(Program.UpdateRepo, Program.UpdateAsset, []) && hits == 0, here);
            else
                Check(@"Update: (bin\ check runs when the self-test is started from a dev build)", true, "not a bin\\ build");

            var plan = await pxdUpdate.FindUpdateAsync(Program.UpdateRepo, Program.UpdateAsset, new Version(1, 0, 0));
            Check("Update: newer release found, Windows zip and its checksum picked", plan is { } pl && pl.Zip == prefix + "zip" && pl.Sum == prefix + "sum", plan?.ToString() ?? "none");
            Check("Update: nothing offered when this copy is current", await pxdUpdate.FindUpdateAsync(Program.UpdateRepo, Program.UpdateAsset, new Version(9, 9, 9)) is null);

            var applied = await pxdUpdate.ApplyAsync(prefix + "zip", prefix + "sum", install, exe, [], start: false);
            Check("Update: files replaced in a temp install folder, user files kept", applied && File.ReadAllText(exe) == "new exe"
                && File.ReadAllText(Path.Combine(install, "lib.dll")) == "new lib" && File.Exists(Path.Combine(install, "extra.dll"))
                && File.ReadAllText(Path.Combine(install, "keep.json")) == "user file");
            pxdUpdate.CleanUp(install);
            Check("Update: set-aside old files cleaned up", Directory.GetFiles(install, "*.pxdold").Length == 0);

            File.WriteAllText(exe, "old exe");
            badSum = true;
            var refused = !await pxdUpdate.ApplyAsync(prefix + "zip", prefix + "sum", install, exe, [], start: false);
            Check("Update: a wrong checksum changes nothing", refused && File.ReadAllText(exe) == "old exe");
        }
        catch (Exception ex)
        {
            Check("Update: no crash", false, ex.Message);
        }
        finally
        {
            Environment.SetEnvironmentVariable("PXD_UPDATE_API", savedApi);
            Environment.SetEnvironmentVariable("PXD_NO_UPDATE", savedNo);
            listener.Stop();
            try { await serving; } catch { /* stopped */ }
        }

        return results;
    }
}
