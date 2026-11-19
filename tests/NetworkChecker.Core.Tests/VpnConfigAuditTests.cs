using System.Net;
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
}
