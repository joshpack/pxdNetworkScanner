using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text;

namespace pxdNetworkScanner;

/// <summary>
/// One copy per user: starting the exe again hands its arguments to the running copy (which brings its window to the
/// front) and exits. A named mutex decides who runs; a named pipe carries the arguments.
/// </summary>
internal static class SingleInstance
{
    private static Mutex? _mutex;

    /// <summary>Base name of the mutex and pipe, unique per app and user.</summary>
    public static string Name(string appId) =>
        appId + "-" + Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(Environment.UserDomainName + "\\" + Environment.UserName)))[..16];

    /// <summary>True when this is the only copy (it keeps running); false when the arguments went to the running copy.</summary>
    public static bool Claim(string name, string[] args)
    {
        _mutex = new Mutex(true, @"Local\" + name, out var first);
        if (first)
            return true;
        _mutex.Dispose();
        _mutex = null;
        // The running copy may still be starting up: give its pipe a moment.
        for (var attempt = 0; attempt < 10; attempt++)
            if (Send(name, args))
                return false;
        return true;   // the other copy isn't answering: start anyway rather than do nothing
    }

    /// <summary>Lets go of the single-instance claim (before handing over to an elevated copy).</summary>
    public static void Release()
    {
        try { _mutex?.ReleaseMutex(); } catch { }
        _mutex?.Dispose();
        _mutex = null;
    }

    /// <summary>Sends <paramref name="args"/> to the copy listening on <paramref name="name"/>.</summary>
    public static bool Send(string name, string[] args)
    {
        try
        {
            using var pipe = new NamedPipeClientStream(".", name, PipeDirection.Out, PipeOptions.CurrentUserOnly);
            pipe.Connect(400);
            // Let the running copy take the foreground (Windows only lets the active app hand it on).
            if (OperatingSystem.IsWindows() && GetNamedPipeServerProcessId(pipe.SafePipeHandle.DangerousGetHandle(), out var pid))
                AllowSetForegroundWindow(pid);
            var bytes = Encoding.UTF8.GetBytes(string.Join("\n", args));
            pipe.Write(bytes);
            pipe.Flush();
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Calls <paramref name="received"/> (on a worker thread) with the arguments of each later start.</summary>
    public static IDisposable Listen(string name, Action<string[]> received)
    {
        var stop = new CancellationTokenSource();
        var thread = new Thread(() =>
        {
            while (!stop.IsCancellationRequested)
            {
                try
                {
                    using var server = new NamedPipeServerStream(name, PipeDirection.In, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
                    server.WaitForConnectionAsync(stop.Token).GetAwaiter().GetResult();
                    using var ms = new MemoryStream();
                    server.CopyTo(ms);
                    var text = Encoding.UTF8.GetString(ms.ToArray());
                    received(text.Length == 0 ? [] : text.Split('\n'));
                }
                catch (OperationCanceledException)
                {
                    return;
                }
                catch
                {
                    Thread.Sleep(200);
                }
            }
        }) { IsBackground = true, Name = "single-instance" };
        thread.Start();
        return new Stopper(stop);
    }

    private sealed class Stopper(CancellationTokenSource stop) : IDisposable
    {
        public void Dispose() => stop.Cancel();
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeServerProcessId(IntPtr pipe, out uint serverProcessId);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AllowSetForegroundWindow(uint processId);
}
