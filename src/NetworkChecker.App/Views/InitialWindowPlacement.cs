using Avalonia;

namespace NetworkChecker.App.Views;

/// <summary>Стартовый размер и положение в физических координатах рабочего пространства монитора.</summary>
internal static class InitialWindowPlacement
{
    internal static (double Width, double Height, PixelPoint Position) Fit(PixelRect workingArea, double scaling,
        double requestedWidth, double requestedHeight)
    {
        var scale = double.IsFinite(scaling) && scaling > 0 ? scaling : 1;
        // Оставляем место системной рамке, заголовку и небольшие поля вокруг окна.
        var maxWidth = Math.Max(1, workingArea.Width / scale - 32);
        var maxHeight = Math.Max(1, workingArea.Height / scale - 72);
        var width = Math.Clamp(requestedWidth, 1, maxWidth);
        var height = Math.Clamp(requestedHeight, 1, maxHeight);
        var x = workingArea.X + (int)Math.Round((workingArea.Width - width * scale) / 2);
        var y = workingArea.Y + (int)Math.Round((workingArea.Height - (height + 40) * scale) / 2);
        return (width, height, new PixelPoint(Math.Max(workingArea.X, x), Math.Max(workingArea.Y, y)));
    }
}
