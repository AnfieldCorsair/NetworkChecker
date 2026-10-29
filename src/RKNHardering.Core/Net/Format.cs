using System.Net;
using System.Text.Json;

namespace RKNHardering.Core.Net;

/// <summary>Маскирование и форматирование значений с учётом режима приватности.</summary>
public static class Masking
{
    public static bool Enabled { get; set; }

    public static string Ip(string? ip)
    {
        if (string.IsNullOrWhiteSpace(ip)) return "—";
        if (!Enabled) return ip;
        if (!IPAddress.TryParse(ip, out var address)) return "•••";
        return address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
            ? string.Join('.', ip.Split('.')[..2]) + ".•••.•••"
            : ip.Length > 12 ? ip[..8] + "…" : "•••";
    }

    public static string Mac(string? mac)
    {
        if (string.IsNullOrWhiteSpace(mac)) return "—";
        return Enabled ? mac[..8] + ":••:••:••" : mac;
    }

    public static string Host(string? host)
    {
        if (string.IsNullOrWhiteSpace(host)) return "—";
        return host;
    }
}

/// <summary>Разбор ответов GeoIP-провайдеров с разной схемой JSON.</summary>
public static class GeoIpParser
{
    public sealed record GeoInfo(string? Ip, string? Country, bool? Hosting, bool? Proxy, string? Isp, string? Org, string? Asn, string? City)
    {
        public bool? IsRussian => Country is null ? null : Country.Equals("RU", StringComparison.OrdinalIgnoreCase);
    }

    private static readonly string[] IpKeys = ["ip", "query", "ipAddress", "ip_address", "YourFuckingIPAddress"];
    private static readonly string[] CountryKeys = ["country_code", "countryCode", "country", "country_code2", "country_code3", "loc"];
    private static readonly string[] HostingKeys = ["is_hosting", "hosting", "isHosting", "is_datacenter", "datacenter"];
    private static readonly string[] ProxyKeys = ["is_proxy", "proxy", "isProxy", "is_vpn", "vpn", "is_tor", "tor", "is_abuser"];
    private static readonly string[] IspKeys = ["isp", "org", "organization", "asn_org"];
    private static readonly string[] AsnKeys = ["asn", "as_number", "asn_number"];
    private static readonly string[] CityKeys = ["city", "town"];

    public static GeoInfo? Parse(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            return new GeoInfo(
                FindString(root, IpKeys),
                FindCountry(root),
                FindBool(root, HostingKeys),
                FindBool(root, ProxyKeys),
                FindString(root, IspKeys),
                FindString(root, ["org", "organization", "as_org"]),
                FindString(root, AsnKeys),
                FindString(root, CityKeys));
        }
        catch
        {
            return null;
        }
    }

    private static string? FindString(JsonElement element, string[] keys)
    {
        foreach (var key in keys)
        {
            if (TryFind(element, key, out var value) && value.ValueKind == JsonValueKind.String)
            {
                var text = value.GetString();
                if (!string.IsNullOrWhiteSpace(text)) return text;
            }
        }
        return null;
    }

    private static string? FindCountry(JsonElement root)
    {
        var code = FindString(root, CountryKeys);
        if (code is null) return null;
        code = code.Trim().ToUpperInvariant();
        return code.Length == 2 ? code : GeoCountries.ToCode(code) ?? code;
    }

    private static bool? FindBool(JsonElement element, string[] keys)
    {
        foreach (var key in keys)
        {
            if (!TryFind(element, key, out var value)) continue;
            switch (value.ValueKind)
            {
                case JsonValueKind.True: return true;
                case JsonValueKind.False: return false;
                case JsonValueKind.String when bool.TryParse(value.GetString(), out var parsed): return parsed;
                case JsonValueKind.Number when value.TryGetInt32(out var number): return number != 0;
            }
        }
        return null;
    }

    private static bool TryFind(JsonElement element, string key, out JsonElement value, int depth = 0)
    {
        value = default;
        if (depth > 4) return false;
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var property in element.EnumerateObject())
                {
                    if (property.Name.Equals(key, StringComparison.OrdinalIgnoreCase))
                    {
                        value = property.Value;
                        return true;
                    }
                }
                foreach (var property in element.EnumerateObject())
                {
                    if (property.Value.ValueKind is JsonValueKind.Object or JsonValueKind.Array &&
                        TryFind(property.Value, key, out value, depth + 1))
                    {
                        return true;
                    }
                }
                break;
            case JsonValueKind.Array:
                foreach (var item in element.EnumerateArray())
                {
                    if (item.ValueKind == JsonValueKind.Object && TryFind(item, key, out value, depth + 1))
                        return true;
                }
                break;
        }
        return false;
    }
}

/// <summary>Мини-конвертер названий стран в ISO-коды (используется в вердикте и GeoIP).</summary>
public static class GeoCountries
{
    private static readonly Dictionary<string, string> NameToCode = new(StringComparer.OrdinalIgnoreCase)
    {
        ["russia"] = "RU", ["russian federation"] = "RU", ["россия"] = "RU",
        ["netherlands"] = "NL", ["germany"] = "DE", ["finland"] = "FI", ["sweden"] = "SE",
        ["united states"] = "US", ["usa"] = "US", ["turkey"] = "TR", ["kazakhstan"] = "KZ",
        ["france"] = "FR", ["poland"] = "PL", ["latvia"] = "LV", ["lithuania"] = "LT",
        ["estonia"] = "EE", ["united kingdom"] = "GB", ["singapore"] = "SG", ["japan"] = "JP",
    };

    private static readonly Dictionary<string, string> CodeToName = new(StringComparer.OrdinalIgnoreCase)
    {
        ["RU"] = "Россия", ["NL"] = "Нидерланды", ["DE"] = "Германия", ["FI"] = "Финляндия",
        ["SE"] = "Швеция", ["US"] = "США", ["TR"] = "Турция", ["KZ"] = "Казахстан",
        ["FR"] = "Франция", ["PL"] = "Польша", ["LV"] = "Латвия", ["LT"] = "Литва",
        ["EE"] = "Эстония", ["GB"] = "Великобритания", ["SG"] = "Сингапур", ["JP"] = "Япония",
    };

    public static string? ToCode(string name) => NameToCode.TryGetValue(name.Trim(), out var code) ? code : null;

    public static string Name(string? code) =>
        code is not null && CodeToName.TryGetValue(code, out var name) ? name : code ?? "—";
}
