using System.Collections.Concurrent;
using Avalonia.Media;

namespace RKNHardering.App;

/// <summary>Кэш кистей для цветов из ViewModel.</summary>
public static class Ui
{
    private static readonly ConcurrentDictionary<string, IBrush> Cache = new();

    public static IBrush Brush(string hex) => Cache.GetOrAdd(hex, key => new SolidColorBrush(Color.Parse(key)));

    public static IBrush Brush(string hex, double opacity) =>
        Cache.GetOrAdd(hex + "@" + opacity, _ => new SolidColorBrush(Color.Parse(hex), opacity));
}
