namespace NetworkChecker.Core.VpnAudit;

public enum VpnProtocol
{
    Vless,
    AmneziaWg,
    Hysteria2,
    SingBoxJson,
    XrayJson,
    LegacyWireGuard,
    LegacyOpenVpn,
    LegacyShadowsocks,
    PacScript,
    Unknown,
}

public enum AuditCategory
{
    Security,
    Leaks,
    Routing,
    TransportDpi,
}

public enum AuditSeverity
{
    Ok,
    Warning,
    Critical,
}

public sealed record XhttpSettings(
    string Mode,
    string Path,
    string? Host,
    string? ExtraRaw,
    bool HasPadding,
    bool HasXmux,
    bool HasDownloadSettings);

public sealed record AmneziaWgSettings(
    int? Jc,
    int? Jmin,
    int? Jmax,
    int? S1,
    int? S2,
    long? H1,
    long? H2,
    long? H3,
    long? H4);

public sealed record TlsSettings(
    string Mode,
    string? Sni,
    string? Fingerprint,
    string? Flow,
    string? PublicKey,
    string? ShortId,
    bool AllowInsecure,
    IReadOnlyList<string> Alpn);

public sealed record NormalizedVpnProfile
{
    public required VpnProtocol Protocol { get; init; }
    public required string ProtocolLabel { get; init; }
    public required string Name { get; init; }
    public string? ServerHost { get; init; }
    public int? ServerPort { get; init; }
    public required string Transport { get; init; }
    public required TlsSettings Tls { get; init; }
    public XhttpSettings? Xhttp { get; init; }
    public AmneziaWgSettings? AmneziaWg { get; init; }
    public string? WsPath { get; init; }
    public string? WsHost { get; init; }
    public int? WsEarlyData { get; init; }
    public string? Obfs { get; init; }
    public bool HasObfsPassword { get; init; }
    public string? PortHopping { get; init; }
    public IReadOnlyList<string> DnsServers { get; init; } = [];
    public IReadOnlyList<string> AllowedIps { get; init; } = [];
    public bool RoutesAllIpv4 { get; init; }
    public bool RoutesAllIpv6 { get; init; }
    public int? Mtu { get; init; }
    public int? PersistentKeepalive { get; init; }
    public bool HasPresharedKey { get; init; }
    public bool HasSniffing { get; init; }
    public bool HasDnsHijack { get; init; }
    public bool HasPrivateBypass { get; init; }
    public IReadOnlyList<string> RawSecrets { get; init; } = [];
    public IReadOnlyList<string> ParseWarnings { get; init; } = [];
}

public sealed record VpnAuditFinding(
    string Id,
    AuditCategory Category,
    AuditSeverity Severity,
    string Title,
    string SimpleSummary,
    string TechnicalDetail,
    string Evidence,
    string Remediation,
    string? PatchSnippet = null,
    string? ProtocolSpec = null);

public sealed record VpnAuditReport(
    DateTimeOffset AnalyzedAt,
    string RawConfig,
    NormalizedVpnProfile Profile,
    IReadOnlyList<VpnAuditFinding> Findings)
{
    public int CriticalCount => Findings.Count(f => f.Severity == AuditSeverity.Critical);
    public int WarningCount => Findings.Count(f => f.Severity == AuditSeverity.Warning);
    public int OkCount => Findings.Count(f => f.Severity == AuditSeverity.Ok);

    public AuditSeverity OverallVerdict =>
        CriticalCount > 0 ? AuditSeverity.Critical :
        WarningCount > 0 ? AuditSeverity.Warning :
        AuditSeverity.Ok;
}

public sealed record SubscriptionNodeAudit(
    int Index,
    string RawUri,
    VpnAuditReport Report);

public sealed record VpnEndpointProbeResult(
    string Host,
    int Port,
    string Sni,
    bool DnsOk,
    IReadOnlyList<string> ResolvedIps,
    long DnsMs,
    bool TcpOk,
    long? TcpMs,
    bool TlsChecked,
    bool TlsOk,
    long? TlsMs,
    string? TlsProtocol,
    string? AlpnProtocol,
    string? CertSubject,
    int? CertDaysRemaining,
    bool SuitableForRealitySni,
    string? Error);
