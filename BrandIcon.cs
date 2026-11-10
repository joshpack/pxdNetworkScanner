using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Media.Imaging;
using ShapePath = Avalonia.Controls.Shapes.Path;

namespace pxdNetworkScanner;

/// <summary>
/// pxd Network Scanner's icon: a radar with its sweep and three devices it found, on a blue-to-cyan tile.
/// Drawn from vector shapes so it stays crisp at every size; used for the window and the exe's .ico.
/// </summary>
public static class BrandIcon
{
    public static Control Build(double size)
    {
        var a = new Canvas { Width = 100, Height = 100 };
        IBrush B(string c) => new SolidColorBrush(Color.Parse(c));
        void Ring(double r, string color, double width) =>
            a.Children.Add(new ShapePath { Data = new EllipseGeometry(new Rect(50 - r, 50 - r, r * 2, r * 2)), Stroke = B(color), StrokeThickness = width });
        void Dot(double x, double y, double r, string color, string? edge = null) =>
            a.Children.Add(new ShapePath { Data = new EllipseGeometry(new Rect(x - r, y - r, r * 2, r * 2)), Fill = B(color), Stroke = edge is null ? null : B(edge), StrokeThickness = edge is null ? 0 : 3 });

        Ring(44, "#E6FFFFFF", 5);
        Ring(30, "#99FFFFFF", 4);
        Ring(16, "#99FFFFFF", 4);
        // The sweep: a fading wedge behind its leading edge.
        a.Children.Add(new ShapePath
        {
            Data = Geometry.Parse("M50,50 L50,6 A44,44 0 0,1 88.1,28 Z"),
            Fill = new LinearGradientBrush
            {
                StartPoint = new RelativePoint(0, 0, RelativeUnit.Relative), EndPoint = new RelativePoint(1, 0.6, RelativeUnit.Relative),
                GradientStops = { new GradientStop(Color.Parse("#10FFFFFF"), 0), new GradientStop(Color.Parse("#90FFFFFF"), 1) },
            },
        });
        a.Children.Add(new ShapePath { Data = Geometry.Parse("M50,50 L88.1,28"), Stroke = B("#FFFFFF"), StrokeThickness = 5, StrokeLineCap = PenLineCap.Round });
        // Devices it found.
        Dot(72, 36, 7.5, "#19F58C", "#0B2A4A");
        Dot(27, 64, 6.5, "#19F58C", "#0B2A4A");
        Dot(63, 77, 6.5, "#FFD23F", "#0B2A4A");
        Dot(50, 50, 5.5, "#FFFFFF");
        return Tile(size, "#3A47D5", "#00C6E0", a, 0.1);
    }

    public static RenderTargetBitmap Render(int size)
    {
        var c = Build(size);
        c.Measure(new Size(size, size));
        c.Arrange(new Rect(0, 0, size, size));
        var bitmap = new RenderTargetBitmap(new PixelSize(size, size), new Vector(96, 96));
        bitmap.Render(c);
        return bitmap;
    }

    public static WindowIcon Window(int size = 64) => new(Render(size));

    /// <summary>Writes a multi-size .ico (PNG entries) for the exe, or a 256 px PNG when the path ends in .png.</summary>
    public static void Write(string path)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        if (path.EndsWith(".png", StringComparison.OrdinalIgnoreCase))
        {
            using var png = File.Create(path);
            Render(256).Save(png, PngBitmapEncoderOptions.Default);
            return;
        }

        int[] sizes = [16, 20, 24, 32, 40, 48, 64, 128, 256];
        var images = sizes.Select(s =>
        {
            using var ms = new MemoryStream();
            Render(s).Save(ms, PngBitmapEncoderOptions.Default);
            return ms.ToArray();
        }).ToList();
        using var w = new BinaryWriter(File.Create(path));
        w.Write((short)0);
        w.Write((short)1);
        w.Write((short)sizes.Length);
        var offset = 6 + 16 * sizes.Length;
        for (var i = 0; i < sizes.Length; i++)
        {
            var b = (byte)(sizes[i] >= 256 ? 0 : sizes[i]);
            w.Write(b);
            w.Write(b);
            w.Write((byte)0);
            w.Write((byte)0);
            w.Write((short)1);
            w.Write((short)32);
            w.Write(images[i].Length);
            w.Write(offset);
            offset += images[i].Length;
        }

        foreach (var img in images) w.Write(img);
    }

    private static Grid Tile(double size, string from, string to, Canvas art, double margin)
    {
        var g = new Grid { Width = size, Height = size };
        g.Children.Add(new Border
        {
            CornerRadius = new CornerRadius(size * 0.22),
            Background = new LinearGradientBrush
            {
                StartPoint = new RelativePoint(0, 0, RelativeUnit.Relative),
                EndPoint = new RelativePoint(1, 1, RelativeUnit.Relative),
                GradientStops = { new GradientStop(Color.Parse(from), 0), new GradientStop(Color.Parse(to), 1) },
            },
        });
        g.Children.Add(new Viewbox { Margin = new Thickness(size * margin), Child = art });
        return g;
    }
}
