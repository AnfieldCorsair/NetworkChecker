using System.Buffers.Binary;
using System.Net;
using System.Net.Security;
using System.Text;
using System.Text.Json;
using VpnChecker.Core.VpnAudit;
using Xunit;

namespace VpnChecker.Core.Tests;

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
    public void XrayJson_WithStringDnsServersAndVnext_ParsesWithoutCrashing()
    {
        // Регрессионный тест: Xray dns.servers содержит строки ("https+local://...", "8.8.8.8", "localhost")
        const string xrayJson = """
            {
              "dns": {
                "servers": [
                  "https+local://1.1.1.1/dns-query",
                  "8.8.8.8",
                  "localhost",
                  { "address": "https://77.88.8.8/dns-query", "tag": "dns-direct" }
                ]
              },
              "outbounds": [
                {
                  "tag": "proxy",
                  "protocol": "vless",
                  "settings": {
                    "vnext": [
                      {
                        "address": "185.100.87.10",
                        "port": 443,
                        "users": [
                          { "id": "9f8e7d6c-5b4a-4321-8765-abcdef012345", "flow": "xtls-rprx-vision" }
                        ]
                      }
                    ]
                  },
                  "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                      "serverName": "www.microsoft.com",
                      "fingerprint": "chrome",
                      "publicKey": "8xR4qT7wY1zB5nL0jH3dG6sA9eU2iO4pM8kF9vN2cAA"
                    }
                  }
                }
              ],
              "routing": {
                "rules": [
                  { "type": "field", "ip": ["geoip:private"], "outboundTag": "direct" }
                ]
              }
            }
            """;

        var report = VpnConfigAuditor.Audit(xrayJson);

        Assert.Equal(VpnProtocol.XrayJson, report.Profile.Protocol);
        Assert.Equal("185.100.87.10", report.Profile.ServerHost);
        Assert.Equal(443, report.Profile.ServerPort);
        Assert.Equal("www.microsoft.com", report.Profile.Tls.Sni);
        Assert.Contains(report.Profile.DnsServers, d => d.Contains("1.1.1.1", StringComparison.Ordinal));
        Assert.Contains(report.Findings, f => f.Id == "json-plain-dns");
        Assert.Contains(report.Findings, f => f.Id == "json-reality-ok");
    }

    [Fact]
    public void NonObjectJsonArray_DoesNotThrow_ReturnsUnknownFinding()
    {
        var report = VpnConfigAuditor.Audit("[\"hello\", 123]");

        Assert.Equal(VpnProtocol.Unknown, report.Profile.Protocol);
        Assert.Contains(report.Findings, f => f.Id == "parse-unknown");
    }

    [Fact]
    public void VmessTrojanShadowsocks_ParseAndAuditCleanly()
    {
        const string vmessJson = "{\"v\":\"2\",\"ps\":\"VMess-Test\",\"add\":\"203.0.113.5\",\"port\":\"443\",\"id\":\"11111111-2222-3333-4444-555555555555\",\"net\":\"ws\",\"tls\":\"tls\",\"sni\":\"cdn.example.com\"}";
        var vmessUri = "vmess://" + Convert.ToBase64String(Encoding.UTF8.GetBytes(vmessJson));
        var vmessReport = VpnConfigAuditor.Audit(vmessUri);

        Assert.Equal(VpnProtocol.Vmess, vmessReport.Profile.Protocol);
        Assert.Equal("203.0.113.5", vmessReport.Profile.ServerHost);
        Assert.Equal(443, vmessReport.Profile.ServerPort);
        Assert.Contains(vmessReport.Findings, f => f.Id == "vmess-rf-legacy");

        const string trojanUri = "trojan://secretpass@203.0.113.9:443?sni=mail.example.com&fp=chrome#Trojan-EU";
        var trojanReport = VpnConfigAuditor.Audit(trojanUri);

        Assert.Equal(VpnProtocol.Trojan, trojanReport.Profile.Protocol);
        Assert.Equal("mail.example.com", trojanReport.Profile.Tls.Sni);
        Assert.Contains(trojanReport.Findings, f => f.Id == "trojan-tls-ok");

        var ssUserInfo = Convert.ToBase64String(Encoding.UTF8.GetBytes("2022-blake3-aes-128-gcm:mySecretKey"));
        var ssReport = VpnConfigAuditor.Audit($"ss://{ssUserInfo}@203.0.113.12:8388#SS2022");

        Assert.Equal(VpnProtocol.LegacyShadowsocks, ssReport.Profile.Protocol);
        Assert.Equal("203.0.113.12", ssReport.Profile.ServerHost);
        Assert.Equal(8388, ssReport.Profile.ServerPort);
        Assert.Contains(ssReport.Findings, f => f.Id == "ss-rf-dpi" && f.Severity == AuditSeverity.Warning);
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

    private static readonly bool[] BoolChoices = [true, false];

    [Fact]
    public void DnsArchitect_AllThreeCores_PassOwnAuditWithZeroFindings()
    {
        foreach (var core in Enum.GetValues<DnsCoreTarget>())
        {
            foreach (var rfSplit in BoolChoices)
            {
                var block = DnsConfigArchitect.GenerateOptimalBlock(new DnsArchitectOptions(core, RfSplitTunneling: rfSplit));
                var findings = DnsConfigArchitect.AuditDnsBlock(block);
                Assert.DoesNotContain(findings, f => f.Severity is AuditSeverity.Critical or AuditSeverity.Warning);
            }
        }

        var singBoxJson = DnsConfigArchitect.GenerateOptimalBlock(new DnsArchitectOptions(DnsCoreTarget.SingBox112));
        var fullReport = VpnConfigAuditor.Audit(singBoxJson);
        Assert.DoesNotContain(fullReport.Findings, f => f.Id == "json-plain-dns");
        Assert.DoesNotContain(fullReport.Findings, f => f.Id == "json-no-sniff");
        Assert.Contains(fullReport.Findings, f => f.Id == "json-encrypted-dns-ok");
    }

    [Fact]
    public void DnsArchitect_NinjaSampleAndDnsBlockOnly_RecognizesNjallaLibreDnsAndLocalhostBootstrap()
    {
        var findings = DnsConfigArchitect.AuditDnsBlock(DnsConfigArchitect.NinjaSampleJson);

        Assert.DoesNotContain(findings, f => f.Severity == AuditSeverity.Critical);
        Assert.Contains(findings, f => f.Id == "dns-ninja-privacy-ok" && f.Severity == AuditSeverity.Ok);
        Assert.Contains(findings, f => f.Id == "dns-localhost-explained" && f.Severity == AuditSeverity.Ok);
        Assert.Contains(findings, f => f.Id == "dns-isolated-block-ok" && f.Severity == AuditSeverity.Ok);

        var xrayOnlyDns = DnsConfigArchitect.GenerateOptimalBlock(new DnsArchitectOptions(
            DnsCoreTarget.XrayCore,
            RfSplitTunneling: true,
            UseFakeIp: false,
            Ipv4Only: true,
            BlockAds: false,
            ProviderProfile: DnsProviderProfile.NinjaPrivacy,
            OutputScope: DnsOutputScope.DnsBlockOnly));

        Assert.Contains("dns.njal.la", xrayOnlyDns, StringComparison.Ordinal);
        Assert.Contains("doh.libredns.gr", xrayOnlyDns, StringComparison.Ordinal);
        Assert.DoesNotContain("\"routing\"", xrayOnlyDns, StringComparison.Ordinal);
    }

    [Fact]
    public void DnsArchitect_SurgicalInjectIntoHappSubscription_ReplacesOnlyDnsAndPreservesOutbounds()
    {
        const string happArray = """
            [
              {
                "remarks": "Node-1",
                "dns": { "servers": ["8.8.8.8"] },
                "outbounds": [{ "tag": "proxy", "protocol": "vless" }]
              },
              {
                "remarks": "Node-2",
                "dns": { "servers": ["1.1.1.1"] },
                "outbounds": [{ "tag": "proxy", "protocol": "hysteria" }]
              }
            ]
            """;

        var okAll = DnsConfigArchitect.TryInjectDnsIntoJsonConfig(
            happArray,
            new DnsArchitectOptions(DnsCoreTarget.XrayCore, ProviderProfile: DnsProviderProfile.NinjaPrivacy, OutputScope: DnsOutputScope.DnsBlockOnly),
            out var patchedAll,
            out _);

        Assert.True(okAll);
        Assert.Contains("dns.njal.la", patchedAll, StringComparison.Ordinal);
        Assert.Contains("doh.libredns.gr", patchedAll, StringComparison.Ordinal);
        Assert.Contains("Node-1", patchedAll, StringComparison.Ordinal);
        Assert.Contains("Node-2", patchedAll, StringComparison.Ordinal);

        var okSingle = DnsConfigArchitect.TryInjectDnsIntoJsonConfig(
            happArray,
            new DnsArchitectOptions(DnsCoreTarget.XrayCore, ProviderProfile: DnsProviderProfile.NinjaPrivacy, OutputScope: DnsOutputScope.DnsBlockOnly),
            out var patchedSingle,
            out _,
            targetNodeIndex: 2,
            extractSingleNodeOnly: true);

        Assert.True(okSingle);
        Assert.StartsWith("{", patchedSingle.TrimStart(), StringComparison.Ordinal);
        Assert.Contains("Node-2", patchedSingle, StringComparison.Ordinal);
        Assert.DoesNotContain("Node-1", patchedSingle, StringComparison.Ordinal);
        Assert.Contains("dns.njal.la", patchedSingle, StringComparison.Ordinal);
    }

    [Fact]
    public void SubscriptionService_PatchSniAndExtractSingleNode_UpdatesRealityServerNameCleanly()
    {
        const string happArray = """
            [
              {
                "remarks": "Loc-1",
                "outbounds": [
                  {
                    "tag": "proxy",
                    "protocol": "vless",
                    "streamSettings": {
                      "network": "xhttp",
                      "security": "reality",
                      "realitySettings": { "serverName": "old.example.com" },
                      "xhttpSettings": { "host": "old.example.com", "path": "/abc" }
                    }
                  }
                ]
              }
            ]
            """;

        var ok = SubscriptionService.TryPatchSniInConfig(
            happArray,
            "www.microsoft.com",
            out var patchedSingle,
            out _,
            targetNodeIndex: 1,
            extractSingleNodeOnly: true);

        Assert.True(ok);
        Assert.StartsWith("{", patchedSingle.TrimStart(), StringComparison.Ordinal);
        Assert.Contains("\"serverName\": \"www.microsoft.com\"", patchedSingle, StringComparison.Ordinal);
        Assert.Contains("\"host\": \"www.microsoft.com\"", patchedSingle, StringComparison.Ordinal);

        var extractedSnis = SubnetSniScanner.ExtractSniDomainsFromConfig(patchedSingle);
        Assert.Contains("www.microsoft.com", extractedSnis);
    }

    [Fact]
    public void SupportTicketBuilder_MasksHomeIpIncludesOsStackAndDetectsWebRtcLeak()
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

        var osReport = WindowsNetworkStackAuditor.EvaluateSnapshots([], []);

        var msg = SupportTicketBuilder.BuildTelegramMessage(new SupportTicketDraft(
            "Сильно режет скорость",
            "Домашний кабель / Wi-Fi",
            "v2rayN",
            "UUID 11111111-2222-3333-4444-555555555555 падает",
            MaskHomeIp: true,
            WithoutVpn: withoutVpn,
            WithVpn: withVpn,
            OsStack: osReport));

        Assert.Contains("PJSC Rostelecom", msg, StringComparison.Ordinal);
        Assert.Contains("95.165.xxx.xxx", msg, StringComparison.Ordinal);
        Assert.DoesNotContain("95.165.120.44", msg, StringComparison.Ordinal);
        Assert.DoesNotContain("11111111-2222-3333-4444-555555555555", msg, StringComparison.Ordinal);
        Assert.Contains("утечка реального домашнего IP", msg, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Сетевой стек ОС Windows", msg, StringComparison.Ordinal);
    }

    [Fact]
    public void BlockingFingerprintDetector_ClassifiesWhitelist16KbAndDnsSpoofing()
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
        var dnsProbes = new List<DnsSpoofProbe>
        {
            new("discord.com", ["127.0.0.1"], ["162.159.135.232"], IsFakeIpActive: false, Suspicious: true, "Подмена на заглушку"),
            new("www.youtube.com", [], ["142.250.74.78"], IsFakeIpActive: false, Suspicious: true, "NXDOMAIN"),
        };

        var matches = BlockingFingerprintDetector.Classify(targets, cutoff, dnsProbes);

        Assert.Contains(matches, m => m.Id == "whitelist_mode" && m.Status == BlockingFingerprintStatus.Detected);
        Assert.Contains(matches, m => m.Id == "cutoff_16kb" && m.Status == BlockingFingerprintStatus.Detected);
        Assert.Contains(matches, m => m.Id == "dns_spoofing" && m.Status == BlockingFingerprintStatus.Detected);
    }

    [Fact]
    public void WindowsNetworkStackAuditor_FiltersNoiseAdaptersFakeDnsAndLocalIpv6()
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
                "vEthernet (WSL)",
                "Hyper-V Virtual Ethernet Adapter",
                "Ethernet",
                IsUp: true,
                IsTunOrVpn: false,
                Ipv4Addresses: ["172.24.0.1"],
                Ipv6Addresses: [],
                DnsServers: [],
                Gateways: [],
                Mtu: 1500),
            new(
                "Ethernet",
                "Intel(R) Ethernet Controller",
                "Ethernet",
                IsUp: true,
                IsTunOrVpn: false,
                Ipv4Addresses: ["192.168.1.10"],
                Ipv6Addresses: ["2a02:6b8::11", "fd00::5"],
                DnsServers: ["192.168.1.1", "8.8.8.8", "fec0:0:0:ffff::1"],
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
        Assert.Equal(1, report.HiddenServiceAdaptersCount);
        Assert.Equal(2, report.Adapters.Count);
        Assert.True(WindowsNetworkStackAuditor.IsGlobalUnicastIpv6(IPAddress.Parse("2a02:6b8::11")));
        Assert.False(WindowsNetworkStackAuditor.IsGlobalUnicastIpv6(IPAddress.Parse("fd00::5")));
        Assert.True(WindowsNetworkStackAuditor.IsWindowsFakeSiteLocalDns(IPAddress.Parse("fec0:0:0:ffff::1")));
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

    [Fact]
    public void HappXrayJsonArraySubscription_ParsesAllProfilesBalancerXhttpAndHysteria2()
    {
        const string happJsonArray = """
            [
              {
                "remarks": "⚡ Автовыбор — включи и забудь",
                "dns": {
                  "servers": [
                    { "address": "77.88.8.8", "port": 53, "domains": ["geosite:category-ru", "domain:ru"], "skipFallback": true },
                    { "address": "https://8.8.8.8/dns-query", "skipFallback": false }
                  ]
                },
                "outbounds": [
                  {
                    "tag": "proxy",
                    "protocol": "vless",
                    "settings": { "vnext": [{ "address": "edge-eu.example.com", "port": 443, "users": [{ "id": "00000000-1111-2222-3333-444444444444" }] }] },
                    "streamSettings": {
                      "network": "xhttp",
                      "security": "reality",
                      "realitySettings": { "serverName": "www.microsoft.com", "fingerprint": "chrome", "publicKey": "8xR4qT7wY1zB5nL0jH3dG6sA9eU2iO4pM8kF9vN2cAA", "shortId": "6ba85179" },
                      "xhttpSettings": { "mode": "auto", "path": "/api/v2/stream", "extra": { "xPaddingBytes": "100-1000", "xmux": { "maxConcurrency": "16-32" } } }
                    }
                  },
                  {
                    "tag": "proxy-2",
                    "protocol": "vless",
                    "settings": { "vnext": [{ "address": "edge-fi.example.com", "port": 443, "users": [{ "id": "00000000-1111-2222-3333-444444444444" }] }] }
                  },
                  { "tag": "DIRECT", "protocol": "freedom" }
                ],
                "routing": {
                  "balancers": [{ "tag": "AUTO", "selector": ["proxy", "proxy-2"], "strategy": { "type": "leastPing" } }],
                  "rules": [
                    { "type": "field", "ip": ["geoip:private", "geoip:ru"], "outboundTag": "DIRECT" },
                    { "type": "field", "domain": ["geosite:category-ru", "domain:ru"], "outboundTag": "DIRECT" }
                  ]
                }
              },
              {
                "remarks": "🌍 Только заграница · запасной протокол",
                "dns": {
                  "servers": [
                    { "address": "https://dns.njal.la/dns-query", "skipFallback": false }
                  ]
                },
                "outbounds": [
                  {
                    "tag": "proxy",
                    "protocol": "hysteria",
                    "settings": { "address": "203.0.113.10", "port": 443, "version": 2 },
                    "streamSettings": {
                      "network": "hysteria",
                      "hysteriaSettings": { "version": 2, "auth": "demo-auth-token-2026" },
                      "security": "tls",
                      "tlsSettings": { "serverName": "hy2.example.com", "fingerprint": "chrome", "alpn": ["h3"] }
                    }
                  }
                ],
                "routing": {
                  "rules": [
                    { "type": "field", "ip": ["geoip:private"], "outboundTag": "DIRECT" }
                  ]
                }
              }
            ]
            """;

        var nodes = VpnConfigAuditor.AuditSubscription(happJsonArray);

        Assert.Equal(2, nodes.Count);

        var first = nodes[0].Report;
        Assert.Equal("⚡ Автовыбор — включи и забудь", first.Profile.Name);
        Assert.Equal("edge-eu.example.com", first.Profile.ServerHost);
        Assert.Equal("XHTTP", first.Profile.Transport);
        Assert.Equal(2, first.Profile.BalancerOutboundCount);
        Assert.True(first.Profile.HasRuSplitRules);
        Assert.NotNull(first.Profile.Xhttp);
        Assert.True(first.Profile.Xhttp!.HasPadding);
        Assert.True(first.Profile.Xhttp.HasXmux);
        Assert.Equal(0, first.CriticalCount);
        Assert.Contains(first.Findings, f => f.Id == "json-auto-balancer-ok");
        Assert.Contains(first.Findings, f => f.Id == "json-xhttp-ok");
        Assert.Contains(first.Findings, f => f.Id == "json-ru-split-ok");
        Assert.Contains(first.Findings, f => f.Id == "json-encrypted-dns-ok");

        var second = nodes[1].Report;
        Assert.Equal("🌍 Только заграница · запасной протокол", second.Profile.Name);
        Assert.Equal("203.0.113.10", second.Profile.ServerHost);
        Assert.Equal(443, second.Profile.ServerPort);
        Assert.Equal("QUIC (UDP)", second.Profile.Transport);
        Assert.Equal("hy2.example.com", second.Profile.Tls.Sni);
        Assert.Contains(second.Findings, f => f.Id == "json-hysteria-ok");
    }

    [Fact]
    public void DirectHttpsSubscriptionUrl_RecognizedWithoutCriticalError()
    {
        const string subUrl = "https://sub.example.com/user/demo-profile-token";

        Assert.True(VpnConfigParser.TryExtractHttpSubscriptionUrl(subUrl, out var uri));
        Assert.Equal("sub.example.com", uri!.Host);

        var report = VpnConfigAuditor.Audit(subUrl);
        Assert.Equal(0, report.CriticalCount);
        Assert.Contains(report.Findings, f => f.Id == "sub-url-detected" && f.Severity == AuditSeverity.Ok);
    }

    [Fact]
    public void VpnConfigAuditor_JsonWithoutPrivateLanRule_DoesNotEmitRouterWarning()
    {
        const string jsonWithoutLanRule = """
            {
              "dns": {
                "servers": ["https://1.1.1.1/dns-query"]
              },
              "outbounds": [
                {
                  "tag": "proxy",
                  "protocol": "vless",
                  "settings": {
                    "vnext": [
                      {
                        "address": "203.0.113.42",
                        "port": 443,
                        "users": [{ "id": "11111111-2222-3333-4444-555555555555", "flow": "xtls-rprx-vision" }]
                      }
                    ]
                  },
                  "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                      "serverName": "www.microsoft.com",
                      "fingerprint": "chrome",
                      "publicKey": "8xR4qT7wY1zB5nL0jH3dG6sA9eU2iO4pM8kF9vN2cAA"
                    }
                  }
                }
              ],
              "routing": {
                "rules": [
                  { "type": "field", "domain": ["geosite:category-ru"], "outboundTag": "direct" }
                ]
              }
            }
            """;

        var report = VpnConfigAuditor.Audit(jsonWithoutLanRule);

        Assert.DoesNotContain(report.Findings, f => f.Id == "json-no-private-bypass");
        Assert.Equal(0, report.CriticalCount);
    }

    [Fact]
    public void DnsArchitect_DefaultIsClassicDoH_AndStrictJsonValidationCatchesTrailingComma()
    {
        var defaultOptions = new DnsArchitectOptions();
        Assert.Equal(DnsProviderProfile.CloudflareGoogle, defaultOptions.ProviderProfile);

        var classicJson = DnsConfigArchitect.GenerateOptimalBlock(defaultOptions);
        Assert.True(DnsConfigArchitect.ValidateStrictJson(classicJson, out _));
        Assert.Contains("https://1.1.1.1/dns-query", classicJson, StringComparison.Ordinal);
        Assert.Contains("https://8.8.8.8/dns-query", classicJson, StringComparison.Ordinal);

        var classicFindings = DnsConfigArchitect.AuditDnsBlock(DnsConfigArchitect.ClassicSampleJson);
        Assert.DoesNotContain(classicFindings, f => f.Severity is AuditSeverity.Critical or AuditSeverity.Warning);
        Assert.Contains(classicFindings, f => f.Id == "dns-valid-json-ok");
        Assert.Contains(classicFindings, f => f.Id == "dns-doh-encrypted-ok");

        const string brokenJsonWithTrailingComma = """
            {
              "dns": {
                "servers": [
                  "https://1.1.1.1/dns-query",
                ]
              }
            }
            """;

        Assert.False(DnsConfigArchitect.ValidateStrictJson(brokenJsonWithTrailingComma, out var err));
        Assert.Contains("Ошибка синтаксиса JSON", err, StringComparison.Ordinal);

        var brokenFindings = DnsConfigArchitect.AuditDnsBlock(brokenJsonWithTrailingComma);
        Assert.Contains(brokenFindings, f => f.Id == "dns-invalid-json" && f.Severity == AuditSeverity.Critical);
    }

    [Fact]
    public void DnsArchitect_InjectsWithAutoDialectSingBoxAndTolerantInput_ProducesStrictValidJson()
    {
        // Sing-box конфиг с комментарием, висячей запятой и отсутствующей секцией "dns"
        const string singBoxDirtyJson = """
            {
              // Комментарий пользователя
              "outbounds": [
                { "type": "vless", "tag": "proxy", "server": "203.0.113.10", "server_port": 443, },
                { "type": "direct", "tag": "direct" },
              ],
              "route": {
                "final": "proxy",
              },
            }
            """;

        var ok = DnsConfigArchitect.TryInjectDnsIntoJsonConfig(
            singBoxDirtyJson,
            new DnsArchitectOptions(DnsCoreTarget.XrayCore, ProviderProfile: DnsProviderProfile.CloudflareGoogle),
            out var patched,
            out var summary);

        Assert.True(ok);
        Assert.Contains("Sing-box", summary, StringComparison.Ordinal);
        Assert.True(DnsConfigArchitect.ValidateStrictJson(patched, out _));

        using var doc = JsonDocument.Parse(patched);
        var dnsServers = doc.RootElement.GetProperty("dns").GetProperty("servers");
        Assert.Equal("https", dnsServers[0].GetProperty("type").GetString());
        Assert.Equal("1.1.1.1", dnsServers[0].GetProperty("server").GetString());
        Assert.Equal("proxy", doc.RootElement.GetProperty("route").GetProperty("final").GetString());

        // Base64-кодированный Xray JSON конфиг тоже должен декодироваться и пропатчиться в строгий JSON
        const string xrayRaw = """
            {
              "remarks": "Base64-Xray",
              "outbounds": [{ "tag": "proxy", "protocol": "vless" }]
            }
            """;
        var b64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(xrayRaw));
        var okB64 = DnsConfigArchitect.TryInjectDnsIntoJsonConfig(
            b64,
            new DnsArchitectOptions(ProviderProfile: DnsProviderProfile.NinjaPrivacy),
            out var patchedB64,
            out _);

        Assert.True(okB64);
        Assert.True(DnsConfigArchitect.ValidateStrictJson(patchedB64, out _));
        Assert.Contains("https://dns.njal.la/dns-query", patchedB64, StringComparison.Ordinal);
        Assert.Contains("Base64-Xray", patchedB64, StringComparison.Ordinal);
    }

    [Fact]
    public void SubnetSniScanner_RawTls13ClientHelloAndServerHelloParsing_HandlesTls13HrrAndTls12()
    {
        var ch = SubnetSniScanner.BuildTls13ClientHello("www.microsoft.com");
        Assert.True(ch.Length > 100);
        Assert.Equal(0x16, ch[0]); // Handshake record
        Assert.Equal(0x01, ch[5]); // ClientHello
        Assert.Contains("www.microsoft.com", Encoding.ASCII.GetString(ch), StringComparison.Ordinal);

        // 1. Синтетический TLS 1.3 ServerHello с supported_versions = 0x0304
        var tls13Sh = BuildSyntheticServerHello(
            cipherSuite: 0x1301,
            selectedVersion: 0x0304,
            isHelloRetryRequest: false);
        var parsed13 = SubnetSniScanner.ParseTls13ServerHello(tls13Sh);
        Assert.True(parsed13.HandshakeReceived);
        Assert.True(parsed13.IsTls13);
        Assert.False(parsed13.IsHelloRetryRequest);
        Assert.Equal((ushort)0x1301, parsed13.CipherSuite);

        // 2. HelloRetryRequest (специальный ServerRandom из RFC 8446)
        var hrrSh = BuildSyntheticServerHello(
            cipherSuite: 0x1301,
            selectedVersion: 0x0304,
            isHelloRetryRequest: true);
        var parsedHrr = SubnetSniScanner.ParseTls13ServerHello(hrrSh);
        Assert.True(parsedHrr.HandshakeReceived);
        Assert.True(parsedHrr.IsTls13);
        Assert.True(parsedHrr.IsHelloRetryRequest);

        // 3. TLS 1.2 ServerHello без TLS 1.3 supported_versions
        var tls12Sh = BuildSyntheticServerHello(
            cipherSuite: 0xC02F,
            selectedVersion: null,
            isHelloRetryRequest: false);
        var parsed12 = SubnetSniScanner.ParseTls13ServerHello(tls12Sh);
        Assert.True(parsed12.HandshakeReceived);
        Assert.False(parsed12.IsTls13);

        // 4. Проверка EvaluateCertificateTrust: None -> true, NameMismatch -> false
        Assert.True(SubnetSniScanner.EvaluateCertificateTrust(null, SslPolicyErrors.None));
        Assert.False(SubnetSniScanner.EvaluateCertificateTrust(null, SslPolicyErrors.RemoteCertificateNameMismatch));
    }

    [Fact]
    public void SubscriptionService_PatchSni_PreservesCyrillicFragmentCustomHostAndHandlesBase64()
    {
        const string uriWithCyrillic =
            "vless://11111111-2222-3333-4444-555555555555@203.0.113.10:443" +
            "?encryption=none&security=reality&type=xhttp&mode=auto&host=custom.cdn.example&sni=old.example.com&fp=chrome#Москва-XHTTP ⚡";

        var okUri = SubscriptionService.TryPatchSniInConfig(uriWithCyrillic, "www.apple.com", out var patchedUri, out _);
        Assert.True(okUri);
        Assert.EndsWith("#Москва-XHTTP ⚡", patchedUri, StringComparison.Ordinal);
        Assert.Contains("sni=www.apple.com", patchedUri, StringComparison.Ordinal);
        // Кастомный host != oldSni должен остаться нетронутым
        Assert.Contains("host=custom.cdn.example", patchedUri, StringComparison.Ordinal);

        // Base64-подписка с 2 узлами
        var b64Sub = Convert.ToBase64String(Encoding.UTF8.GetBytes(uriWithCyrillic + "\n" +
            "trojan://pass@203.0.113.20:443?sni=old2.example.com#Финляндия-Reserve"));
        var okB64 = SubscriptionService.TryPatchSniInConfig(b64Sub, "learn.microsoft.com", out var patchedB64, out _);
        Assert.True(okB64);
        Assert.Contains("sni=learn.microsoft.com", patchedB64, StringComparison.Ordinal);
        Assert.Contains("#Москва-XHTTP ⚡", patchedB64, StringComparison.Ordinal);
        Assert.Contains("#Финляндия-Reserve", patchedB64, StringComparison.Ordinal);

        // JSON с балансировщиком (2 прокси-узла + freedom) и кастомным xhttpSettings.host
        const string multiOutboundJson = """
            {
              "outbounds": [
                {
                  "tag": "proxy-1",
                  "protocol": "vless",
                  "streamSettings": {
                    "network": "xhttp",
                    "security": "reality",
                    "realitySettings": { "serverName": "old.example.com" },
                    "xhttpSettings": { "host": "custom.backend.example", "path": "/api" }
                  }
                },
                {
                  "tag": "proxy-2",
                  "protocol": "vless",
                  "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": { "serverName": "old.example.com" }
                  }
                },
                { "tag": "direct", "protocol": "freedom" }
              ]
            }
            """;

        var okJson = SubscriptionService.TryPatchSniInConfig(multiOutboundJson, "www.nvidia.com", out var patchedJson, out _);
        Assert.True(okJson);
        Assert.True(DnsConfigArchitect.ValidateStrictJson(patchedJson, out _));
        Assert.Contains("\"host\": \"custom.backend.example\"", patchedJson, StringComparison.Ordinal);
        Assert.DoesNotContain("old.example.com", patchedJson, StringComparison.Ordinal);
    }

    [Fact]
    public void SupportTicketBuilder_SupportsMultiSelectSymptomsAndOmitsSpecificNodeDetails()
    {
        var activeAudit = VpnConfigAuditor.Audit(
            "vless://11111111-2222-3333-4444-555555555555@203.0.113.99:443?security=reality&type=xhttp&mode=auto&sni=secret-node-sni.example.com&fp=chrome&pbk=8xR4qT7wY1zB5nL0jH3dG6sA9eU2iO4pM8kF9vN2cAA#Specific-Node-99");
        var rtt = new RttBenchmarkResult(
            "203.0.113.99",
            443,
            "203.0.113.99",
            12,
            3,
            3,
            0,
            40,
            45,
            50,
            50,
            3,
            [new RttSample(1, true, 40), new RttSample(2, true, 45), new RttSample(3, true, 50)]);

        var draft = new SupportTicketDraft(
            Symptom: "Fallback",
            ConnectionType: "Мобильный интернет (4G / LTE)",
            ClientApp: "Happ (Windows / iOS / Android)",
            UserComment: "Проблема на всех локациях",
            MaskHomeIp: true,
            ActiveReport: activeAudit,
            RttBenchmark: rtt,
            Symptoms:
            [
                "Сильно режет скорость (Download/Upload падает почти в ноль)",
                "Соединение обрывается через 10–30 секунд (подозрение на 16 КБ ТСПУ)",
            ]);

        var telegram = SupportTicketBuilder.BuildTelegramMessage(draft);
        var markdown = SupportTicketBuilder.BuildFullMarkdownReport(draft);

        Assert.Contains("Проблемы с интернетом / ВПН:", telegram, StringComparison.Ordinal);
        Assert.Contains("- Сильно режет скорость", telegram, StringComparison.Ordinal);
        Assert.Contains("- Соединение обрывается через 10–30 секунд", telegram, StringComparison.Ordinal);

        // Указание конкретного узла, SNI и TCP RTT не должно попадать в отчёт
        Assert.DoesNotContain("203.0.113.99", telegram, StringComparison.Ordinal);
        Assert.DoesNotContain("secret-node-sni.example.com", telegram, StringComparison.Ordinal);
        Assert.DoesNotContain("Specific-Node-99", telegram, StringComparison.Ordinal);
        Assert.DoesNotContain("TCP RTT", telegram, StringComparison.Ordinal);

        Assert.DoesNotContain("203.0.113.99", markdown, StringComparison.Ordinal);
        Assert.DoesNotContain("secret-node-sni.example.com", markdown, StringComparison.Ordinal);
        Assert.DoesNotContain("TCP RTT", markdown, StringComparison.Ordinal);
    }

    [Fact]
    public void IpReputationProbe_ExtractsAllEndpointsFromHappJsonArrayAndBalancerAndUris()
    {
        const string happArray = """
            [
              {
                "remarks": "⚡ Автовыбор",
                "outbounds": [
                  {
                    "tag": "proxy-nl",
                    "protocol": "vless",
                    "settings": { "vnext": [{ "address": "nl-edge.example.com", "port": 443 }] }
                  },
                  {
                    "tag": "proxy-de",
                    "protocol": "vless",
                    "settings": { "vnext": [{ "address": "185.220.101.7", "port": 8443 }] }
                  },
                  { "tag": "direct", "protocol": "freedom" }
                ]
              },
              {
                "remarks": "🌍 Hysteria2",
                "outbounds": [
                  {
                    "tag": "hy2-fi",
                    "protocol": "hysteria",
                    "settings": { "address": "203.0.113.55", "port": 443 }
                  }
                ]
              }
            ]
            """;

        var endpoints = IpReputationProbe.ExtractAllEndpointsFromConfig(happArray);
        Assert.Equal(3, endpoints.Count);
        Assert.Equal("nl-edge.example.com", endpoints[0].RawHost);
        Assert.Equal("185.220.101.7", endpoints[1].RawHost);
        Assert.Equal(8443, endpoints[1].Port);
        Assert.Equal("203.0.113.55", endpoints[2].RawHost);

        const string uriList = """
            vless://11111111-2222-3333-4444-555555555555@198.51.100.11:443?security=reality&type=xhttp#NL-1
            hy2://secret@198.51.100.22:443?sni=hy2.example.com#FI-2
            """;
        var uriEndpoints = IpReputationProbe.ExtractAllEndpointsFromConfig(uriList);
        Assert.Equal(2, uriEndpoints.Count);
        Assert.Equal("198.51.100.11", uriEndpoints[0].RawHost);
        Assert.Equal("198.51.100.22", uriEndpoints[1].RawHost);
    }

    [Fact]
    public void IpReputationProbe_ParsesYouTubeGlAndGoogleCaptchaAndDetectsRuGeoPoisoning()
    {
        const string ytPayload = """
            )]}'
            {"responseContext":{"serviceTrackingParams":[]},"INNERTUBE_CONTEXT_GL":"RU","INNERTUBE_CONTEXT_HL":"en"}
            """;
        var ytGl = IpReputationProbe.ParseYouTubeGlCode(ytPayload);
        Assert.Equal("RU", ytGl);

        var (searchGl, hasCaptcha) = IpReputationProbe.ParseGoogleSearchRegionAndCaptcha(
            "https://www.google.com/sorry/index?continue=https://www.google.com/",
            429,
            "<html><body>g-recaptcha{\"gl\":\"RU\"}</body></html>");
        Assert.True(hasCaptcha);
        Assert.Equal("RU", searchGl);

        // Зарубежный IP (NL), но YouTube выдал GL=RU -> КРИТИЧНО: прокажённая метка RU
        var poisoned = IpReputationProbe.EvaluateGoogleGeoVerdict(
            physicalCountryCode: "NL",
            youtubeGl: "RU",
            googleRegion: "RU",
            hasCaptcha: false,
            routingChannelUsed: "Активный TUN",
            probeExecuted: true);
        Assert.True(poisoned.IsRuGeoPoisoned);
        Assert.Contains("прокажённая метка RU", poisoned.VerdictTitle, StringComparison.OrdinalIgnoreCase);

        // Зарубежный IP (DE) и YouTube GL=DE -> Чисто
        var clean = IpReputationProbe.EvaluateGoogleGeoVerdict(
            physicalCountryCode: "DE",
            youtubeGl: "DE",
            googleRegion: "DE",
            hasCaptcha: false,
            routingChannelUsed: "Активный TUN",
            probeExecuted: true);
        Assert.False(clean.IsRuGeoPoisoned);
        Assert.False(clean.HasGoogleCaptchaBlock);
        Assert.Equal("DE", clean.DetectedGlCode);
    }

    [Fact]
    public void IpReputationProbe_Builds4ProviderConsensusWithMajorityHostingAndAnyProxy()
    {
        var samples = new List<GeoProviderSample>
        {
            new("ipwho.is", true, "185.220.101.7", "NL", "Netherlands", "Amsterdam", "AS210644", "AEZA GROUP", IsHosting: true, IsProxyOrVpn: false, ElapsedMs: 42),
            new("ip-api.com", true, "185.220.101.7", "NL", "Netherlands", "Amsterdam", "AS210644", "AEZA GROUP", IsHosting: true, IsProxyOrVpn: true, ElapsedMs: 51),
            new("ipinfo.io", true, "185.220.101.7", "NL", "Netherlands", "Amsterdam", "AS210644", "AEZA GROUP", IsHosting: false, IsProxyOrVpn: false, ElapsedMs: 39),
            new("Cloudflare Trace", true, "185.220.101.7", "NL", "NL", "Edge AMS", null, "Cloudflare Edge (AMS)", IsHosting: null, IsProxyOrVpn: null, ElapsedMs: 18),
        };

        var googleVerdict = IpReputationProbe.EvaluateGoogleGeoVerdict("NL", "RU", "RU", false, "TUN", true);
        var consensus = IpReputationProbe.BuildConsensus("185.220.101.7", samples, googleVerdict, "AMS");

        Assert.Equal("185.220.101.7", consensus.ConsensusIp);
        Assert.Equal("NL", consensus.ConsensusCountryCode);
        Assert.True(consensus.MajorityHosting); // 2 из 3 (>= 50%)
        Assert.Equal(2, consensus.HostingPositiveCount);
        Assert.Equal(3, consensus.HostingKnownCount);
        Assert.True(consensus.AnyProxyOrVpn); // 1 из 3 (Any Vote)
        Assert.True(consensus.IpConsistencyOk);

        var (highRuBleed, high16Kb, _, _) = IpReputationProbe.ClassifySubnetRisks("NL", "AS210644", "AEZA GROUP", true, true);
        Assert.True(highRuBleed);
        Assert.False(high16Kb);

        var (hetznerRuBleed, hetzner16Kb, _, _) = IpReputationProbe.ClassifySubnetRisks("DE", "AS24940", "Hetzner Online GmbH", true, false);
        Assert.False(hetznerRuBleed);
        Assert.True(hetzner16Kb);
    }

    [Fact]
    public void IpReputationProbe_FourSignalGoogleProbeDetectsPremiumGeminiFooterAndSwJsData()
    {
        // 1. Positional sw.js_data parser
        const string swJsPositional = ")]}'\n[[\"1\",[[\"en\",\"RU\",\"10\",\"20\"]]]]";
        Assert.Equal("RU", IpReputationProbe.ParseYouTubeGlCode(swJsPositional));

        // 2. YouTube Premium availability
        Assert.False(IpReputationProbe.ParseYouTubePremiumAvailability("<html>YouTube Premium is not available in your country.</html>"));
        Assert.True(IpReputationProbe.ParseYouTubePremiumAvailability("<html>Try YouTube Premium Free · €12.99/month</html>"));

        // 3. Google Gemini availability
        Assert.False(IpReputationProbe.ParseGeminiAvailability("https://gemini.google.com/unsupported", 200, "<html></html>"));
        Assert.False(IpReputationProbe.ParseGeminiAvailability("https://gemini.google.com/app", 403, "<html>Gemini isn't currently supported in your country</html>"));
        Assert.True(IpReputationProbe.ParseGeminiAvailability("https://gemini.google.com/app", 200, "<html><title>Google Gemini</title><script>window.WIZ_global_data={};</script></html>"));

        // 4. Google Search footer region (EU consent bypass)
        var ruFooter = IpReputationProbe.ParseGoogleSearchRegionDetailed(
            "https://www.google.com/?hl=en&gws_rd=cr",
            200,
            "<html><footer><div class=\"uU7dJb\">Russia</div></footer></html>");
        Assert.Equal("RU", ruFooter.RegionCode);
        Assert.Equal("Russia", ruFooter.FooterLabel);
        Assert.False(ruFooter.HasCaptcha);

        var nlFooter = IpReputationProbe.ParseGoogleSearchRegionDetailed(
            "https://www.google.com/?hl=en&gws_rd=cr",
            200,
            "<html><footer><div class=\"uU7dJb\">Netherlands</div></footer></html>");
        Assert.Equal("NL", nlFooter.RegionCode);
        Assert.Equal("Netherlands", nlFooter.FooterLabel);

        // 5. Foreign IP (NL) where YouTube GL didn't fire, but BOTH YouTube Premium=false and Gemini=false -> IsRuGeoPoisoned = true
        var silentPoison = IpReputationProbe.EvaluateGoogleGeoVerdict(
            physicalCountryCode: "NL",
            youtubeGl: null,
            googleRegion: null,
            hasCaptcha: false,
            routingChannelUsed: "Активный TUN",
            probeExecuted: true,
            youtubePremiumAvailable: false,
            geminiAccessible: false,
            googleFooterCountry: null);
        Assert.True(silentPoison.IsRuGeoPoisoned);
        Assert.NotNull(silentPoison.SignalChecks);
        Assert.Equal(6, silentPoison.SignalChecks!.Count);

        // 6. Clean foreign IP (DE) with all 6 signals green
        var cleanAll = IpReputationProbe.EvaluateGoogleGeoVerdict(
            physicalCountryCode: "DE",
            youtubeGl: "DE",
            googleRegion: "DE",
            hasCaptcha: false,
            routingChannelUsed: "Активный TUN",
            probeExecuted: true,
            youtubePremiumAvailable: true,
            geminiAccessible: true,
            googleFooterCountry: "Germany",
            aiStudioAccessible: true,
            aiStudioDetail: "API gateway OK",
            googlePlayCurrency: "EUR",
            googlePlayCountry: "DE",
            googlePlayPaidAvailable: true,
            googleTermsCountry: "DE",
            googleTermsLabel: "Germany");
        Assert.False(cleanAll.IsRuGeoPoisoned);
        Assert.False(cleanAll.AiAccessDivergesFromRuTag);
        Assert.True(cleanAll.ProbeSucceeded);
        Assert.NotNull(cleanAll.SignalChecks);
        Assert.Equal(6, cleanAll.SignalChecks!.Count);
        Assert.All(cleanAll.SignalChecks!, s => Assert.False(s.IsAlert));
    }

    [Fact]
    public void IpReputationProbe_SixSignalParsersAndDivergenceWorkCorrectly()
    {
        // 1. Google Play currency & paid availability
        var playRu = IpReputationProbe.ParseGooglePlayRegionAndCurrency(
            "<html><meta itemprop=\"priceCurrency\" content=\"RUB\" /></html>");
        Assert.Equal("RUB", playRu.CurrencyCode);
        Assert.Equal("RU", playRu.CountryCode);
        Assert.False(playRu.PaidAppsAvailable);

        var playDe = IpReputationProbe.ParseGooglePlayRegionAndCurrency(
            "<html>{\"priceCurrency\":\"EUR\",\"gl\":\"DE\"}</html>");
        Assert.Equal("EUR", playDe.CurrencyCode);
        Assert.Equal("DE", playDe.CountryCode);
        Assert.True(playDe.PaidAppsAvailable);

        // 2. Google Terms jurisdiction parser
        var termsRu = IpReputationProbe.ParseGoogleTermsCountry(
            "<html><div>Country version: Russia</div></html>");
        Assert.Equal("RU", termsRu.CountryCode);
        Assert.Equal("Russia", termsRu.CountryLabel);

        var termsNl = IpReputationProbe.ParseGoogleTermsCountry(
            "<html><div>Country version: Netherlands</div></html>");
        Assert.Equal("NL", termsNl.CountryCode);

        // 3. Google AI Studio + API gateway parser
        var aiBlocked = IpReputationProbe.ParseAiStudioAvailability(
            "https://aistudio.google.com/prompts/new_chat",
            200,
            "<html></html>",
            400,
            "{\"error\":{\"status\":\"FAILED_PRECONDITION\",\"message\":\"User location is not supported for the API use.\"}}");
        Assert.False(aiBlocked.Accessible);

        var aiAllowed = IpReputationProbe.ParseAiStudioAvailability(
            "https://aistudio.google.com/prompts/new_chat",
            200,
            "<html></html>",
            403,
            "{\"error\":{\"status\":\"PERMISSION_DENIED\",\"message\":\"Method doesn't allow unregistered callers\"}}");
        Assert.True(aiAllowed.Accessible);

        // 4. Divergence: RU-tagged foreign NL IP where AI Studio STILL allows access
        var divergent = IpReputationProbe.EvaluateGoogleGeoVerdict(
            physicalCountryCode: "NL",
            youtubeGl: "RU",
            googleRegion: "RU",
            hasCaptcha: false,
            routingChannelUsed: "Активный TUN",
            probeExecuted: true,
            youtubePremiumAvailable: false,
            geminiAccessible: false,
            googleFooterCountry: "Russia",
            aiStudioAccessible: true,
            aiStudioDetail: "API gateway пропустил IP",
            googlePlayCurrency: "RUB",
            googlePlayCountry: "RU",
            googlePlayPaidAvailable: false,
            googleTermsCountry: "RU",
            googleTermsLabel: "Russia");
        Assert.True(divergent.IsRuGeoPoisoned);
        Assert.True(divergent.AiStudioAccessible);
        Assert.False(divergent.GeminiAccessible);
        Assert.True(divergent.AiAccessDivergesFromRuTag);
        Assert.Contains("AI Studio пускает", divergent.VerdictTitle, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void IpReputationProbe_RdapParserAndFourTierRiskScaleClassifyHonestly()
    {
        const string rdapRuFootprintJson = """
            {
              "country": "NL",
              "name": "AEZA-NL-NET",
              "handle": "185.10.20.0 - 185.10.20.255",
              "entities": [
                {
                  "handle": "ORG-AGL12-RU",
                  "vcardArray": ["vcard", [
                    ["fn", {}, "text", "AEZA GROUP LLC"],
                    ["email", {}, "text", "noc@example.ru"]
                  ]]
                }
              ]
            }
            """;

        var rdapRu = IpReputationProbe.ParseRdapIpResponse(rdapRuFootprintJson);
        Assert.Equal("NL", rdapRu.CountryCode);
        Assert.True(rdapRu.HasRuFootprint);
        Assert.Contains("AEZA", rdapRu.OrgOrMaintainer ?? string.Empty, StringComparison.OrdinalIgnoreCase);

        // Tier 1: CriticalRu when RIPE/RDAP shows RU footprint on foreign NL IP
        var critical = IpReputationProbe.ClassifySubnetRisksDetailed("NL", "AS99999", "Unknown Hosting", true, false, rdapRu);
        Assert.Equal(RuBleedRiskTier.CriticalRu, critical.RiskTier);
        Assert.True(critical.HighRuGoogleBleedRisk);

        // Tier 2: HighRisk when known VPN/Proxy flag is true
        var highProxy = IpReputationProbe.ClassifySubnetRisksDetailed("DE", "AS24940", "Hetzner Online GmbH", true, true, null);
        Assert.Equal(RuBleedRiskTier.HighRisk, highProxy.RiskTier);
        Assert.True(highProxy.HighRuGoogleBleedRisk);

        // Tier 3: MediumDatacenterUnverified for unknown datacenter (NEVER falsely Low!)
        var mediumDc = IpReputationProbe.ClassifySubnetRisksDetailed("DE", "AS24940", "Hetzner Online GmbH", true, false, null);
        Assert.Equal(RuBleedRiskTier.MediumDatacenterUnverified, mediumDc.RiskTier);
        Assert.False(mediumDc.HighRuGoogleBleedRisk);

        // Tier 4: LowCleanIsp only for non-hosting, non-proxy clean residential/ISP with no RU footprint
        var cleanIsp = IpReputationProbe.ClassifySubnetRisksDetailed("DE", "AS3320", "Deutsche Telekom AG", false, false, null);
        Assert.Equal(RuBleedRiskTier.LowCleanIsp, cleanIsp.RiskTier);
        Assert.False(cleanIsp.HighRuGoogleBleedRisk);
    }

    private static readonly byte[] TestHrrRandom =
    [
        0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
        0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
        0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
        0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
    ];

    private static byte[] BuildSyntheticServerHello(ushort cipherSuite, ushort? selectedVersion, bool isHelloRetryRequest)
    {
        var body = new List<byte>
        {
            0x03,
            0x03, // legacy_version
        };

        body.AddRange(isHelloRetryRequest ? TestHrrRandom : new byte[32]);

        body.Add(0); // session_id_len = 0
        Span<byte> cs = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(cs, cipherSuite);
        body.Add(cs[0]);
        body.Add(cs[1]);
        body.Add(0); // compression = 0

        if (selectedVersion.HasValue)
        {
            // extensions_len = 6 (type 2 + len 2 + val 2)
            body.Add(0x00);
            body.Add(0x06);
            body.Add(0x00);
            body.Add(0x2B); // supported_versions
            body.Add(0x00);
            body.Add(0x02);
            Span<byte> ver = stackalloc byte[2];
            BinaryPrimitives.WriteUInt16BigEndian(ver, selectedVersion.Value);
            body.Add(ver[0]);
            body.Add(ver[1]);
        }

        var hsLen = body.Count;
        var recLen = 4 + hsLen;
        var packet = new List<byte>
        {
            0x16, 0x03, 0x03,
            (byte)(recLen >> 8), (byte)(recLen & 0xFF),
            0x02, // ServerHello
            (byte)((hsLen >> 16) & 0xFF), (byte)((hsLen >> 8) & 0xFF), (byte)(hsLen & 0xFF),
        };
        packet.AddRange(body);
        return [.. packet];
    }
}
