using System.Text;
using NetworkChecker.Core.VpnAudit;
using Xunit;

namespace NetworkChecker.Core.Tests;

public sealed class VpnConfigAuditTests
{
    [Fact]
    public void VlessXhttpReality_ValidConfig_PassesCoreDpiCheck()
    {
        const string uri =
            "vless://9f8e7d6c-5b4a-4321-8765-abcdef012345@1.1.1.1:443" +
            "?encryption=none&security=reality&type=xhttp&mode=auto&path=/api/v2/s" +
            "&sni=www.microsoft.com&fp=chrome&pbk=8xR4qT7wY1zB5nL0jH3dG6sA9eU2iO4pM8kF9vN2cAA&sid=a1b2c3d4#XHTTP-Test";

        var report = VpnConfigAuditor.Audit(uri);

        Assert.Equal(VpnProtocol.Vless, report.Profile.Protocol);
        Assert.Equal("XHTTP", report.Profile.Transport);
        Assert.Equal(0, report.CriticalCount);
        Assert.Contains(report.Findings, f => f.Id == "vless-xhttp-ok");
    }

    [Fact]
    public void VlessTcpReality_MissingVisionAndInsecure_FlagsCritical()
    {
        const string uri =
            "vless://9f8e7d6c-5b4a-4321-8765-abcdef012345@1.1.1.1:8443" +
            "?encryption=none&security=reality&type=tcp&sni=1.1.1.1&pbk=short&allowInsecure=1#Broken-TCP";

        var report = VpnConfigAuditor.Audit(uri);

        Assert.Contains(report.Findings, f => f.Id == "sec-allow-insecure" && f.Severity == AuditSeverity.Critical);
        Assert.Contains(report.Findings, f => f.Id == "vless-tcp-no-vision" && f.Severity == AuditSeverity.Critical);
        Assert.Contains(report.Findings, f => f.Id == "reality-bad-sni" && f.Severity == AuditSeverity.Critical);
        Assert.Contains(report.Findings, f => f.Id == "reality-bad-pbk" && f.Severity == AuditSeverity.Critical);
    }

    [Fact]
    public void AmneziaWg_S1Plus56EqualsS2_FlagsCriticalCollision()
    {
        const string conf = """
            [Interface]
            PrivateKey = cF9vN2xK8mR4qT7wY1zB5nL0jH3dG6sA9eU2iO4pM8k=
            Address = 10.8.1.2/32
            Jc = 4
            Jmin = 50
            Jmax = 1000
            S1 = 30
            S2 = 86
            H1 = 101
            H2 = 102
            H3 = 103
            H4 = 104

            [Peer]
            PublicKey = xK8mR4qT7wY1zB5nL0jH3dG6sA9eU2iO4pM8kF9vN2c=
            Endpoint = 198.51.100.10:51820
            AllowedIPs = 0.0.0.0/0
            """;

        var report = VpnConfigAuditor.Audit(conf);

        Assert.Equal(VpnProtocol.AmneziaWg, report.Profile.Protocol);
        Assert.Contains(report.Findings, f => f.Id == "awg-s1-s2-collision" && f.Severity == AuditSeverity.Critical);
        Assert.Contains(report.Findings, f => f.Id == "wg-no-dns" && f.Severity == AuditSeverity.Critical);
        Assert.Contains(report.Findings, f => f.Id == "wg-ipv6-leak" && f.Severity == AuditSeverity.Critical);
    }

    [Fact]
    public void Hysteria2_WithoutSalamanderAndPortHopping_WarnsUdpRfLimits()
    {
        const string uri = "hy2://pass123@198.51.100.20:443?sni=example.com#HY2-Node";

        var report = VpnConfigAuditor.Audit(uri);

        Assert.Equal(VpnProtocol.Hysteria2, report.Profile.Protocol);
        Assert.Contains(report.Findings, f => f.Id == "hy2-udp-rf-warning");
        Assert.Contains(report.Findings, f => f.Id == "hy2-no-salamander");
        Assert.Contains(report.Findings, f => f.Id == "hy2-no-mport");
    }

    [Fact]
    public void SubscriptionBase64_DecodesMultipleNodes()
    {
        const string plain =
            "vless://11111111-2222-3333-4444-555555555555@1.1.1.1:443?security=reality&type=xhttp&mode=auto&sni=www.microsoft.com&fp=chrome&pbk=8xR4qT7wY1zB5nL0jH3dG6sA9eU2iO4pM8kF9vN2cAA#Node1\n" +
            "hy2://secret@198.51.100.20:443?sni=example.com&obfs=salamander&obfs-password=xyz#Node2";
        var b64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(plain));

        var results = VpnConfigAuditor.AuditSubscription(b64);

        Assert.Equal(2, results.Count);
        Assert.Equal(VpnProtocol.Vless, results[0].Report.Profile.Protocol);
        Assert.Equal(VpnProtocol.Hysteria2, results[1].Report.Profile.Protocol);
    }

    [Fact]
    public void LegacyOpenVpn_ReturnsRfDpiBlockingCritical()
    {
        const string ovpn = "client\ndev tun\nproto udp\nremote 198.51.100.1 1194\n";
        var report = VpnConfigAuditor.Audit(ovpn);

        Assert.Equal(VpnProtocol.LegacyOpenVpn, report.Profile.Protocol);
        Assert.Contains(report.Findings, f => f.Id == "legacy-openvpn-rf" && f.Severity == AuditSeverity.Critical);
    }

    [Fact]
    public void SubscriptionBulkPatch_FixesAllowInsecureAddsFpAndVisionAndDeduplicates()
    {
        const string raw =
            "vless://11111111-2222-3333-4444-555555555555@1.1.1.1:443?security=reality&type=tcp&sni=www.microsoft.com&pbk=8xR4qT7wY1zB5nL0jH3dG6sA9eU2iO4pM8kF9vN2cAA&allowInsecure=1#NodeA\n" +
            "vless://11111111-2222-3333-4444-555555555555@1.1.1.1:443?security=reality&type=tcp&sni=www.microsoft.com&pbk=8xR4qT7wY1zB5nL0jH3dG6sA9eU2iO4pM8kF9vN2cAA#NodeA-Dup\n" +
            "vless://22222222-3333-4444-5555-666666666666@cloudflare.com:443?security=reality&type=xhttp&mode=broken&sni=www.microsoft.com&pbk=8xR4qT7wY1zB5nL0jH3dG6sA9eU2iO4pM8kF9vN2cAA#NodeB";

        var patched = SubscriptionService.ApplyBulkPatch(raw);

        Assert.Equal(3, patched.BeforeCount);
        Assert.Equal(2, patched.AfterCount);
        Assert.Equal(1, patched.FixedAllowInsecure);
        Assert.Equal(2, patched.AddedFpChrome);
        Assert.Equal(1, patched.AddedVisionFlow);
        Assert.Equal(1, patched.FixedXhttpMode);
        Assert.Equal(1, patched.RemovedDuplicates);
        Assert.DoesNotContain("allowInsecure", patched.PatchedText, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("flow=xtls-rprx-vision", patched.PatchedText, StringComparison.Ordinal);
        Assert.Contains("mode=auto", patched.PatchedText, StringComparison.Ordinal);
    }

    [Fact]
    public void DnsArchitect_SingBox112Block_PassesOwnAuditWithoutCriticalIssues()
    {
        var json = DnsConfigArchitect.GenerateOptimalBlock(new DnsArchitectOptions(DnsCoreTarget.SingBox112));
        var findings = DnsConfigArchitect.AuditDnsBlock(json);

        Assert.DoesNotContain(findings, f => f.Severity == AuditSeverity.Critical);
        Assert.Contains("default_domain_resolver", json, StringComparison.Ordinal);
        Assert.Contains("hijack-dns", json, StringComparison.Ordinal);

        var fullReport = VpnConfigAuditor.Audit(json);
        Assert.DoesNotContain(fullReport.Findings, f => f.Id == "json-plain-dns");
        Assert.DoesNotContain(fullReport.Findings, f => f.Id == "json-no-sniff");
        Assert.Contains(fullReport.Findings, f => f.Id == "json-encrypted-dns-ok");
    }

    [Fact]
    public void SupportTicketBuilder_MasksHomeIpAndDetectsWebRtcLeak()
    {
        var withoutVpn = new SupportNetworkSnapshot(
            "without_vpn",
            DateTimeOffset.UtcNow,
            "95.165.120.44",
            "Russia",
            "Moscow",
            "PJSC Rostelecom",
            "AS12389",
            new SupportSpeedSample(92.4, 84.1, 14, "Cloudflare Speed API"));

        var withVpn = new SupportNetworkSnapshot(
            "with_vpn",
            DateTimeOffset.UtcNow,
            "185.100.87.12",
            "Germany",
            "Frankfurt",
            "Hetzner Online GmbH",
            "AS24940",
            new SupportSpeedSample(12.3, 8.5, 68, "Cloudflare Speed API"),
            ["95.165.120.44"]);

        var msg = SupportTicketBuilder.BuildTelegramMessage(new SupportTicketDraft(
            "Сильно режет скорость",
            "Домашний кабель / Wi-Fi",
            "v2rayN",
            "UUID 11111111-2222-3333-4444-555555555555 падает",
            MaskHomeIp: true,
            WithoutVpn: withoutVpn,
            WithVpn: withVpn));

        Assert.Contains("PJSC Rostelecom", msg, StringComparison.Ordinal);
        Assert.Contains("95.165.xxx.xxx", msg, StringComparison.Ordinal);
        Assert.DoesNotContain("95.165.120.44", msg, StringComparison.Ordinal);
        Assert.DoesNotContain("11111111-2222-3333-4444-555555555555", msg, StringComparison.Ordinal);
        Assert.Contains("утечка реального домашнего IP", msg, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void BlockingFingerprintDetector_ClassifiesWhitelistAnd16KbCutoff()
    {
        var targets = new List<BlockingTargetProbe>
        {
            new("Яндекс", "ya.ru", "ru_whitelist", true, 24),
            new("ВКонтакте", "vk.com", "ru_whitelist", true, 31),
            new("Госуслуги", "www.gosuslugi.ru", "ru_whitelist", true, 40),
            new("Wikipedia", "www.wikipedia.org", "global_infra", false, 4200, "timeout"),
            new("GitHub", "github.com", "global_infra", false, 4200, "timeout"),
            new("Discord", "discord.com", "restricted_rf", false, 4200, "timeout"),
        };
        var cutoff = new List<CutoffStepProbe>
        {
            new(4096, 4096, true, 85),
            new(16384, 16384, true, 140),
            new(65536, 16384, false, 5500, "timeout"),
            new(524288, 16384, false, 5500, "timeout"),
        };

        var matches = BlockingFingerprintDetector.Classify(targets, cutoff);

        Assert.Contains(matches, m => m.Id == "whitelist_mode" && m.Status == BlockingFingerprintStatus.Detected);
        Assert.Contains(matches, m => m.Id == "cutoff_16kb" && m.Status == BlockingFingerprintStatus.Detected);
    }

    [Fact]
    public void WindowsNetworkStackAuditor_DetectsDnsLeakAndGlobalIpv6OutsideTun()
    {
        var adapters = new List<NetworkAdapterSnapshot>
        {
            new(
                "sing-box-tun",
                "Wintun Userspace Tunnel",
                "Tunnel",
                IsUp: true,
                IsTunOrVpn: true,
                Ipv4Addresses: ["172.19.0.1"],
                Ipv6Addresses: [],
                DnsServers: ["172.19.0.2"],
                Gateways: [],
                Mtu: 1500),
            new(
                "Ethernet",
                "Intel(R) Ethernet Controller",
                "Ethernet",
                IsUp: true,
                IsTunOrVpn: false,
                Ipv4Addresses: ["192.168.1.10"],
                Ipv6Addresses: ["2a02:6b8::11"],
                DnsServers: ["192.168.1.1", "8.8.8.8"],
                Gateways: ["192.168.1.1"],
                Mtu: 1500),
        };
        var ports = new List<LocalProxyPortStatus>
        {
            new(2080, "Sing-box / NekoBox Mixed", IsListening: true, "127.0.0.1"),
        };

        var report = WindowsNetworkStackAuditor.EvaluateSnapshots(adapters, ports);

        Assert.True(report.HasActiveTunAdapter);
        Assert.True(report.HasPlainIspDnsOutsideTun);
        Assert.True(report.HasGlobalIpv6OutsideTun);
        Assert.Contains(report.Findings, f => f.Id == "os-tun-high-mtu" && f.Severity == AuditSeverity.Warning);
        Assert.Contains(report.Findings, f => f.Id == "os-dns-leak-risk" && f.Severity == AuditSeverity.Warning);
        Assert.Contains(report.Findings, f => f.Id == "os-ipv6-outside-tun" && f.Severity == AuditSeverity.Critical);
    }

    [Fact]
    public void SubnetSniScanner_BuildsSlash24NeighborsAndRejectsPrivateIps()
    {
        var neighbors = SubnetSniScanner.BuildSlash24Addresses("185.100.87.10", maxCount: 10);

        Assert.Equal(10, neighbors.Count);
        Assert.DoesNotContain("185.100.87.10", neighbors);
        Assert.Contains("185.100.87.9", neighbors);
        Assert.Contains("185.100.87.11", neighbors);

        var privateNeighbors = SubnetSniScanner.BuildSlash24Addresses("192.168.1.10", maxCount: 10);
        Assert.Empty(privateNeighbors);
    }
}

