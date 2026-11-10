using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Avalonia.Threading;
using pxdNetworkScanner.Views;

namespace pxdNetworkScanner;

public partial class App : Application
{
    public override void Initialize()
    {
        AvaloniaXamlLoader.Load(this);
        Styles.Add(pxdStandard.pxdChrome.Styles());   // caption-button hover colours of the pxd title bar
    }

    public override void OnFrameworkInitializationCompleted()
    {
        // The self-test runs on the headless platform without a desktop lifetime.
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime lifetime)
        {
            var window = new MainWindow();
            pxdStandard.pxdChrome.RememberPlacement(window, "main");
            lifetime.MainWindow = window;

            // Started again: bring this window to the front (back to maximized if it was).
            var restoreTo = window.WindowState;
            window.PropertyChanged += (_, e) =>
            {
                if (e.Property == Window.WindowStateProperty && window.WindowState != WindowState.Minimized)
                    restoreTo = window.WindowState;
            };
            var listener = SingleInstance.Listen(SingleInstance.Name(Program.AppId), _ => Dispatcher.UIThread.Post(() =>
            {
                if (window.WindowState == WindowState.Minimized) window.WindowState = restoreTo;
                window.Activate();
            }));
            lifetime.Exit += (_, _) => listener.Dispose();
        }

        base.OnFrameworkInitializationCompleted();
    }
}
