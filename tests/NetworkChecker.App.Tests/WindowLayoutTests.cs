using Avalonia;
using NetworkChecker.App.Views;
using Xunit;

namespace NetworkChecker.App.Tests;

public class WindowLayoutTests
{
    [Theory]
    [InlineData(1366, 728, 1.0)]
    [InlineData(1920, 1040, 1.25)]
    [InlineData(1366, 728, 1.5)]
    [InlineData(800, 600, 2.0)]
    public void Window_is_fitted_to_working_area_with_dpi(int width, int height, double scale)
    {
        var area = new PixelRect(-1920, 40, width, height);
        var p = InitialWindowPlacement.Fit(area, scale, 1400, 900);
        Assert.True(p.Width > 0 && p.Height > 0);
        Assert.True(p.Position.X >= area.X && p.Position.Y >= area.Y);
        Assert.True(p.Position.X + p.Width * scale <= area.Right);
        Assert.True(p.Position.Y + (p.Height + 40) * scale <= area.Bottom);
    }

    [Fact]
    public void Invalid_scale_is_treated_as_one()
    {
        var area = new PixelRect(0, 0, 1280, 720);
        Assert.Equal(InitialWindowPlacement.Fit(area, 1, 1400, 900),
            InitialWindowPlacement.Fit(area, double.NaN, 1400, 900));
    }
}
