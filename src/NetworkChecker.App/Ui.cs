using System.Collections.Concurrent;
using Avalonia.Media;
using Avalonia.Media.Immutable;

namespace NetworkChecker.App;

/// <summary>Кэш кистей для цветов из ViewModel.</summary>
public static class Ui
{
    private static readonly ConcurrentDictionary<string, IBrush> Cache = new();

    public static IBrush Brush(string hex) => Cache.GetOrAdd(hex, key => new ImmutableSolidColorBrush(Color.Parse(key)));

    public static IBrush Brush(string hex, double opacity) =>
        Cache.GetOrAdd(hex + "@" + opacity, _ => new ImmutableSolidColorBrush(Color.Parse(hex), opacity));
}
