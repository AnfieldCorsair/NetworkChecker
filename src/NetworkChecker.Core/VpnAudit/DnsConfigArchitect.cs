using System.Text;
using System.Text.Json;

namespace NetworkChecker.Core.VpnAudit;

public enum DnsCoreTarget
{
    SingBox112,
    XrayCore,
    ClashMihomo,
}

public sealed record DnsArchitectOptions(
    DnsCoreTarget Core = DnsCoreTarget.SingBox112,
    bool RfSplitTunneling = true,
    bool UseFakeIp = true,
    bool Ipv4Only = true,
    bool BlockAds = false);

/// <summary>
/// Конструктор и аудитор оптимального блока DNS под российские реалии:
/// защита от DNS-петли (bootstrap), DoH через proxy против подмены ТСПУ,
/// локальный RU DoH при split-tunneling, hijack-dns + sniff и защита от AAAA/IPv6-утечек.
/// </summary>
public static class DnsConfigArchitect
{
    private static readonly JsonSerializerOptions PrettyJson = new() { WriteIndented = true };
    private static readonly string[] SingBoxRuDomainSuffixes = [".ru", ".su", ".xn--p1ai"];
    private static readonly string[] SingBoxRuRuleSets = ["geosite-category-ru", "geosite-category-gov-ru"];
    private static readonly string[] QueryTypeIpv4Only = ["A"];
    private static readonly string[] QueryTypeDualStack = ["A", "AAAA"];
    private static readonly string[] XrayFakeDnsNonCn = ["geosite:geolocation-!cn"];
    private static readonly string[] XrayFakeDnsAll = ["geosite:all"];
    private static readonly string[] XrayRuDomains = ["domain:ru", "domain:su", "domain:xn--p1ai", "geosite:category-ru"];
    private static readonly string[] XrayRuExpectIps = ["geoip:ru"];
    private static readonly string[] XrayInboundRemote = ["dns-remote"];
    private static readonly string[] XrayInboundDirect = ["dns-direct"];
    private static readonly string[] XrayGeoIpPrivate = ["geoip:private"];

    public static string GenerateOptimalBlock(DnsArchitectOptions? options = null)
    {
        var opt = options ?? new DnsArchitectOptions();
        return opt.Core switch
        {
            DnsCoreTarget.SingBox112 => GenerateSingBox112(opt),
            DnsCoreTarget.XrayCore => GenerateXray(opt),
            DnsCoreTarget.ClashMihomo => GenerateClashYaml(opt),
            _ => GenerateSingBox112(opt),
        };
    }

    public static IReadOnlyList<VpnAuditFinding> AuditDnsBlock(string rawDns)
    {
        var findings = new List<VpnAuditFinding>();
        if (string.IsNullOrWhiteSpace(rawDns)) return findings;
        var lower = rawDns.ToLowerInvariant();

        var hasEncrypted = lower.Contains("https://", StringComparison.Ordinal) ||
                           lower.Contains("\"type\": \"https\"", StringComparison.Ordinal) ||
                           lower.Contains("tls://", StringComparison.Ordinal);

        if (!hasEncrypted && (lower.Contains("8.8.8.8", StringComparison.Ordinal) || lower.Contains("1.1.1.1", StringComparison.Ordinal)))
        {
            findings.Add(new VpnAuditFinding(
                "dns-plain-udp", AuditCategory.Leaks, AuditSeverity.Critical,
                "Открытый UDP DNS (8.8.8.8 / 1.1.1.1) — уязвим к DNS-спуфингу ТСПУ",
                "UDP-запросы на порт 53 перехватываются и подменяются провайдером.",
                "Отсутствует DoH/DoT обёртка.",
                "UDP :53",
                "Используйте DoH (https://1.1.1.1/dns-query) с маршрутизацией через proxy."));
        }

        var hasProxyDetour = lower.Contains("\"detour\": \"proxy\"", StringComparison.Ordinal) ||
                             lower.Contains("#proxy", StringComparison.Ordinal) ||
                             lower.Contains("\"outboundtag\": \"proxy\"", StringComparison.Ordinal);
        if (!hasProxyDetour)
        {
            findings.Add(new VpnAuditFinding(
                "dns-no-proxy-detour", AuditCategory.Leaks, AuditSeverity.Critical,
                "Зарубежный DNS не привязан к proxy-туннелю",
                "Запросы к 1.1.1.1 / 8.8.8.8 напрямую из РФ блокируются или раскрывают SNI провайдеру.",
                "Не найдены detour: proxy / #PROXY / outboundTag: proxy.",
                "Отсутствует привязка к proxy",
                "Маршрутизируйте мировой DoH строго через proxy, оставив в direct только bootstrap и RU-домены."));
        }

        var hasBootstrap = lower.Contains("default_domain_resolver", StringComparison.Ordinal) ||
                           lower.Contains("proxy-server-nameserver", StringComparison.Ordinal) ||
                           lower.Contains("https+local://", StringComparison.Ordinal) ||
                           lower.Contains("dns-bootstrap", StringComparison.Ordinal);
        if (!hasBootstrap)
        {
            findings.Add(new VpnAuditFinding(
                "dns-no-bootstrap", AuditCategory.Routing, AuditSeverity.Warning,
                "Не задан bootstrap-резолвер для домена ВПН-сервера",
                "При указании сервера доменом возможна DNS-петля на старте туннеля.",
                "Отсутствует default_domain_resolver / proxy-server-nameserver.",
                "Нет bootstrap DNS",
                "Задайте отдельный direct/local резолвер для домена самого ВПН-сервера."));
        }

        if (!lower.Contains("hijack-dns", StringComparison.Ordinal) && !lower.Contains("dns-hijack", StringComparison.Ordinal))
        {
            findings.Add(new VpnAuditFinding(
                "dns-no-hijack", AuditCategory.Leaks, AuditSeverity.Warning,
                "Отсутствует hijack-dns / dns-hijack",
                "Приложения со вшитым 8.8.8.8 в TUN-режиме будут обходить правила DNS.",
                "Правило перехвата порта 53 не найдено.",
                "Нет hijack-dns",
                "Добавьте правило перехвата протокола dns (action: hijack-dns)."));
        }

        return findings;
    }

    private static string GenerateSingBox112(DnsArchitectOptions opt)
    {
        var strategy = opt.Ipv4Only ? "ipv4_only" : "prefer_ipv4";
        var servers = new List<object>
        {
            new { tag = "dns-remote", type = "https", server = "1.1.1.1", server_port = 443, path = "/dns-query", detour = "proxy" },
            new { tag = "dns-direct", type = "https", server = "77.88.8.8", server_port = 443, path = "/dns-query", detour = "direct" },
            new { tag = "dns-bootstrap", type = "udp", server = "77.88.8.8" },
        };
        if (opt.UseFakeIp)
        {
            servers.Add(new { tag = "dns-fakeip", type = "fakeip", inet4_range = "198.18.0.0/15" });
        }

        var dnsRules = new List<object>();
        if (opt.BlockAds) dnsRules.Add(new { rule_set = "geosite-category-ads-all", action = "reject" });
        if (opt.RfSplitTunneling)
        {
            dnsRules.Add(new { domain_suffix = SingBoxRuDomainSuffixes, rule_set = SingBoxRuRuleSets, server = "dns-direct" });
        }
        if (opt.UseFakeIp) dnsRules.Add(new { query_type = opt.Ipv4Only ? QueryTypeIpv4Only : QueryTypeDualStack, server = "dns-fakeip" });

        var doc = new
        {
            dns = new { servers, rules = dnsRules, final = "dns-remote", strategy, independent_cache = true, reverse_mapping = true },
            route = new
            {
                default_domain_resolver = "dns-bootstrap",
                auto_detect_interface = true,
                rules = new object[]
                {
                    new { action = "sniff" },
                    new { protocol = "dns", action = "hijack-dns" },
                    new { ip_is_private = true, outbound = "direct" },
                },
                final = "proxy",
            },
        };
        return JsonSerializer.Serialize(doc, PrettyJson);
    }

    private static string GenerateXray(DnsArchitectOptions opt)
    {
        var servers = new List<object>();
        if (opt.UseFakeIp) servers.Add(new { address = "fakedns", domains = opt.RfSplitTunneling ? XrayFakeDnsNonCn : XrayFakeDnsAll });
        servers.Add(new { address = "https://1.1.1.1/dns-query", tag = "dns-remote" });
        if (opt.RfSplitTunneling)
        {
            servers.Add(new { address = "https+local://77.88.8.8/dns-query", domains = XrayRuDomains, expectIPs = XrayRuExpectIps, skipFallback = true, tag = "dns-direct" });
        }
        var doc = new
        {
            dns = new { servers, queryStrategy = opt.Ipv4Only ? "UseIPv4" : "UseIP", disableFallbackIfMatch = true },
            routing = new
            {
                domainStrategy = "IPIfNonMatch",
                rules = new object[]
                {
                    new { type = "field", inboundTag = XrayInboundRemote, outboundTag = "proxy" },
                    new { type = "field", inboundTag = XrayInboundDirect, outboundTag = "direct" },
                    new { type = "field", ip = XrayGeoIpPrivate, outboundTag = "direct" },
                },
            },
        };
        return JsonSerializer.Serialize(doc, PrettyJson);
    }

    private static string GenerateClashYaml(DnsArchitectOptions opt)
    {
        var sb = new StringBuilder();
        sb.AppendLine(opt.Ipv4Only ? "ipv6: false" : "ipv6: true");
        sb.AppendLine("sniffer:\n  enable: true\n  parse-pure-ip: true");
        sb.AppendLine("tun:\n  enable: true\n  stack: mixed\n  auto-route: true\n  dns-hijack: [\"any:53\", \"tcp://any:53\"]");
        sb.AppendLine("dns:");
        sb.AppendLine("  enable: true");
        sb.AppendLine(opt.Ipv4Only ? "  ipv6: false" : "  ipv6: true");
        sb.AppendLine("  respect-rules: true");
        sb.AppendLine(opt.UseFakeIp ? "  enhanced-mode: fake-ip" : "  enhanced-mode: redir-host");
        sb.AppendLine("  default-nameserver:\n    - 77.88.8.8");
        sb.AppendLine("  proxy-server-nameserver:\n    - https://common.dot.dns.yandex.net/dns-query#DIRECT");
        sb.AppendLine("  nameserver:\n    - https://1.1.1.1/dns-query#PROXY\n    - https://dns.quad9.net/dns-query#PROXY");
        if (opt.RfSplitTunneling)
        {
            sb.AppendLine("  nameserver-policy:\n    \"geosite:category-ru,+.ru,+.su,+.xn--p1ai\":\n      - https://common.dot.dns.yandex.net/dns-query#DIRECT");
        }
        return sb.ToString();
    }
}
