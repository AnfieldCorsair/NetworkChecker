namespace NetworkChecker.Core.Options;

/// <summary>
/// Каталог маркеров, по которым ищутся клиенты обхода блокировок.
/// Аналог VpnAppCatalog/VpnAppClassifier из Android-версии, адаптированный под Windows.
/// </summary>
public sealed class VpnClientCatalog
{
    public sealed record Entry(string Name, string Category, string[] Markers);

    public IReadOnlyList<Entry> Entries { get; } =
    [
        new("WireGuard", "vpn", ["wireguard", "wg.exe", "wireguard.exe"]),
        new("OpenVPN", "vpn", ["openvpn", "openvpn-gui", "ovpn"]),
        new("Amnezia VPN", "vpn", ["amnezia"]),
        new("Outline", "vpn", ["outline", "shadowsocks"]),
        new("NordVPN", "vpn", ["nordvpn", "nordlynx"]),
        new("Proton VPN", "vpn", ["protonvpn", "proton.vpn"]),
        new("ExpressVPN", "vpn", ["expressvpn"]),
        new("Surfshark", "vpn", ["surfshark"]),
        new("Windscribe", "vpn", ["windscribe"]),
        new("Mullvad", "vpn", ["mullvad"]),
        new("Cloudflare WARP", "vpn", ["cloudflare warp", "warp-svc", "1.1.1.1"]),
        new("AdGuard VPN", "vpn", ["adguard vpn"]),
        new("Kaspersky Secure Connection", "vpn", ["kaspersky secure connection"]),
        new("SoftEther VPN", "vpn", ["softether"]),
        new("Tap-windows / TAP драйвер", "driver", ["tap-windows", "tap0901", "ovpn-dco"]),
        new("Wintun", "driver", ["wintun"]),
        new("v2rayN / v2rayA", "proxy", ["v2rayn", "v2raya", "v2ray"]),
        new("Xray / Xray-core", "proxy", ["xray"]),
        new("Shadowsocks (Windows)", "proxy", ["shadowsocks"]),
        new("Nekoray / NekoBox", "proxy", ["nekoray", "nekobox"]),
        new("Clash / Clash Verge / Mihomo", "proxy", ["clash", "mihomo", "clash verge"]),
        new("sing-box", "proxy", ["sing-box", "singbox"]),
        new("Hiddify", "proxy", ["hiddify"]),
        new("Lantern", "proxy", ["lantern"]),
        new("Psiphon", "proxy", ["psiphon"]),
        new("Tor Browser / Tor", "proxy", ["tor browser", "tor.exe"]),
        new("GoodbyeDPI", "anti-censor", ["goodbyedpi"]),
        new("zapret / winws", "anti-censor", ["zapret", "winws"]),
        new("SpoofDPI", "anti-censor", ["spoofdpi"]),
        new("ByeDPI", "anti-censor", ["byedpi"]),
        new("Green Tunnel", "anti-censor", ["green tunnel"]),
        new("ProxyThorn", "proxy", ["proxy thorn", "proxythorn"]),
        new("Outline SDK клиенты", "proxy", ["outline-sdk"]),
        new("Netch", "proxy", ["netch"]),
        new("SSTap", "proxy", ["sstap"]),
        new("WireSock", "vpn", ["wiresock"]),
        new("Tun2socks", "driver", ["tun2socks"]),
        // Протоколы и клиенты, появившиеся в публичных разборах ТСПУ 2025–2026 гг.
        new("AmneziaWG", "vpn", ["amneziawg", "amnezia wg"]),
        new("Hysteria 2", "proxy", ["hysteria2", "hysteria"]),
        new("TUIC", "proxy", ["tuic.exe", "tuic-client", "tuic-v5"]),
        new("Juicity", "proxy", ["juicity"]),
        new("Mieru", "proxy", ["mieru"]),
        new("NaiveProxy", "proxy", ["naiveproxy"]),
        new("Trojan / Trojan-Go", "proxy", ["trojan-go", "trojan.exe"]),
        new("ShadowTLS / Cloak / obfs4", "proxy", ["shadowtls", "cloak-client", "obfs4proxy", "meek-client"]),
        new("XHTTP / XTLS", "proxy", ["xhttp", "xtls-rprx"]),
        new("Throne / FlClash / Karing / Exclave", "proxy", ["throne", "flclash", "karing", "exclave", "owenclave"]),
        new("Happ / Incy / Hiddify Next", "proxy", ["happ.exe", "incy.exe", "hiddify-next"]),
        new("Proxifier / ProxyCap / SSTap-подобные", "proxy", ["proxifier", "proxycap", "sockscap"]),
        new("Локальные HTTP/SOCKS-серверы", "proxy", ["privoxy", "3proxy", "squid for windows", "mitmproxy", "fiddler", "charles proxy", "burp suite"]),
        new("WinDivert / WinPKFilter", "driver", ["windivert", "winpkfilter"]),
    ];

    /// <summary>Возвращает совпавшую запись каталога либо null.</summary>
    public Entry? Match(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        foreach (var entry in Entries)
        {
            foreach (var marker in entry.Markers)
            {
                if (text.Contains(marker, StringComparison.OrdinalIgnoreCase))
                    return entry;
            }
        }
        return null;
    }

    public bool IsVpnRelated(string? text) => Match(text) is not null;

    /// <summary>Маркеры для поиска в именах служб и драйверов.</summary>
    public IEnumerable<string> AllMarkers => Entries.SelectMany(e => e.Markers);
}
