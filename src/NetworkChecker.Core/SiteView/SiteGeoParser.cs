using System.Text.Json;
using NetworkChecker.Core.Net;

namespace NetworkChecker.Core.SiteView;

/// <summary>
/// Разбор ответа GeoIP-сервиса в «то, что видит сайт». Ключи у провайдеров разные
/// (ipapi.is, ipwho.is, ipinfo.io, 2ip), поэтому ищем по именам полей рекурсивно,
/// а не по жёсткой схеме — иначе половина сервисов молча теряется.
/// </summary>
public static class SiteGeoParser
{
    private static readonly string[] IpKeys = ["ip", "query", "ipAddress", "ip_address", "YourFuckingIPAddress"];
    private static readonly string[] CountryKeys = ["country_code", "countryCode", "countryCode2", "country", "country_code2"];
    private static readonly string[] CityKeys = ["city", "town", "settlement"];
    private static readonly string[] RegionKeys = ["region", "region_name", "regionName", "state", "province"];
    private static readonly string[] CompanyKeys = ["company", "company_name", "org", "organization", "asn_org", "as_org", "as_name", "isp", "provider"];
    private static readonly string[] AsnKeys = ["asn", "as_number", "asn_number", "asNumber"];
    private static readonly string[] TimezoneKeys = ["timezone", "time_zone", "timeZone", "tz", "timezone_id"];
    private static readonly string[] HostingKeys = ["is_hosting", "hosting", "isHosting", "is_datacenter", "datacenter", "is_dc"];
    private static readonly string[] ProxyKeys = ["is_proxy", "proxy", "isProxy", "is_vpn", "vpn", "is_tor", "tor", "is_abuser"];
    private static readonly string[] IspKeys = ["isp", "carrier", "provider"];

    public static SiteGeo? Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;

        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(json);
        }
        catch (JsonException)
        {
            return null;
        }

        using (doc)
        {
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return null;

            var ip = FindString(root, IpKeys);
            if (string.IsNullOrWhiteSpace(ip)) return null;

            var asn = NormalizeAsn(FindString(root, AsnKeys));
            var company = FindString(root, CompanyKeys);
            // ipapi.is кладёт организацию внутрь строки ASN: «AS396982 Google LLC».
            if (asn is not null && asn.Contains(' ', StringComparison.Ordinal))
            {
                var parts = asn.Split(' ', 2);
                asn = parts[0];
                company ??= parts.Length > 1 ? parts[1].Trim() : null;
            }

            return new SiteGeo(
                Ip: ip.Trim(),
                Country: NormalizeCountry(FindString(root, CountryKeys)),
                City: FindString(root, CityKeys),
                Region: FindString(root, RegionKeys),
                Company: company,
                Asn: asn,
                Timezone: FindTimezone(root),
                Hosting: FindBool(root, HostingKeys),
                Proxy: FindBool(root, ProxyKeys),
                Isp: FindString(root, IspKeys));
        }
    }

    private static string? NormalizeAsn(string? asn)
    {
        if (string.IsNullOrWhiteSpace(asn)) return null;
        var text = asn.Trim();
        return text.StartsWith("AS", StringComparison.OrdinalIgnoreCase) ? "AS" + text[2..].Trim() : text;
    }

    private static string? NormalizeCountry(string? country)
    {
        if (string.IsNullOrWhiteSpace(country)) return null;
        var code = country.Trim().ToUpperInvariant();
        return code.Length == 2 ? code : GeoCountries.ToCode(code) ?? code;
    }

    /// <summary>Часовой пояс бывает строкой («Europe/Moscow») или объектом (ipwho.is: `timezone.id`).</summary>
    private static string? FindTimezone(JsonElement root)
    {
        foreach (var key in TimezoneKeys)
        {
            if (!TryFind(root, key, out var value, depth: 0)) continue;
            var text = value.ValueKind switch
            {
                JsonValueKind.String => value.GetString(),
                JsonValueKind.Object => FindString(value, ["id", "name", "timezone", "tz"]),
                _ => null,
            };
            if (!string.IsNullOrWhiteSpace(text) && text.Contains('/', StringComparison.Ordinal)) return text.Trim();
        }
        return null;
    }

    private static string? FindString(JsonElement element, string[] keys)
    {
        foreach (var key in keys)
        {
            if (!TryFind(element, key, out var value, depth: 0)) continue;
            if (value.ValueKind == JsonValueKind.String)
            {
                var text = value.GetString();
                if (!string.IsNullOrWhiteSpace(text)) return text.Trim();
            }
            else if (value.ValueKind == JsonValueKind.Number)
            {
                return value.GetRawText();
            }
        }
        return null;
    }

    private static bool? FindBool(JsonElement element, string[] keys)
    {
        foreach (var key in keys)
        {
            if (!TryFind(element, key, out var value, depth: 0)) continue;
            if (value.ValueKind is JsonValueKind.True) return true;
            if (value.ValueKind is JsonValueKind.False) return false;
            if (value.ValueKind == JsonValueKind.String)
            {
                var text = value.GetString()?.Trim();
                if (bool.TryParse(text, out var parsed)) return parsed;
                if (text is "1" or "yes") return true;
                if (text is "0" or "no") return false;
            }
            if (value.ValueKind == JsonValueKind.Number) return value.GetInt32() != 0;
        }
        return null;
    }

    /// <summary>Ищет поле по имени на любом уровне вложенности (но не глубже трёх — этого хватает всем провайдерам).</summary>
    private static bool TryFind(JsonElement element, string key, out JsonElement found, int depth)
    {
        found = default;
        if (depth > 3 || element.ValueKind != JsonValueKind.Object) return false;

        foreach (var property in element.EnumerateObject())
        {
            if (property.Name.Equals(key, StringComparison.OrdinalIgnoreCase))
            {
                found = property.Value;
                return true;
            }
        }

        foreach (var property in element.EnumerateObject())
        {
            if (property.Value.ValueKind == JsonValueKind.Object
                && TryFind(property.Value, key, out found, depth + 1))
            {
                return true;
            }
        }

        return false;
    }
}
