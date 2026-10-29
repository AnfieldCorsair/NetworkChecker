using System.Globalization;

namespace NetworkChecker.Core.Net;

/// <summary>Стабильное представление ASN для карты хопов, без географических предположений.</summary>
public static class TraceGraph
{
    private static readonly string[] Colors = ["#63B4FF", "#70E4BB", "#F7C65C", "#D59BF6", "#FF967D", "#82D9DF", "#F2A6CC", "#A9CE75"];

    public static string? NormalizeAsn(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var text = value.Trim();
        if (text.StartsWith("AS", StringComparison.OrdinalIgnoreCase)) text = text[2..];
        return uint.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var number) && number > 0
            ? "AS" + number.ToString(CultureInfo.InvariantCulture) : null;
    }

    /// <summary>Цвет — группировка, не оценка риска; у разных ASN возможны совпадения палитры.</summary>
    public static string ColorForAsn(string? value)
    {
        var normalized = NormalizeAsn(value);
        if (normalized is null) return "#8090A4";
        uint hash = 2166136261;
        foreach (var c in normalized) hash = unchecked((hash ^ c) * 16777619);
        return Colors[hash % (uint)Colors.Length];
    }
}
