<div align="center">

# Контур ВПН (NetworkChecker V2)

**Deep VPN Configuration Auditor, TSPU 16 KB & DPI Fingerprint Scanner, RFC 8446 TLS 1.3 Reality SNI Hunter, and IP Reputation + Google `RU` Geo-Poisoning Inspector**

[![.NET](https://img.shields.io/badge/.NET-10.0-512BD4?logo=dotnet)](https://dotnet.microsoft.com/)
[![C#](https://img.shields.io/badge/C%23-14-239120?logo=csharp)](https://learn.microsoft.com/dotnet/csharp/)
[![Avalonia UI](https://img.shields.io/badge/Avalonia_UI-12.1.4-8B5CF6)](https://avaloniaui.net/)
[![Platform](https://img.shields.io/badge/Platform-Windows_x64_%7C_Web-0078D6?logo=windows)](https://github.com/AnfieldCorsair/NetworkChecker)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

**[Русская документация (Полное руководство со скриншотами) →](./README.ru.md)**

</div>

---

## Overview

**Контур ВПН (NetworkChecker V2 v2.1.0)** is a comprehensive VPN & network diagnostic suite engineered for modern censorship-circumvention protocols (**VLESS Reality XHTTP / SplitHTTP**, **VLESS TCP Vision**, **AmneziaWG**, **Hysteria2 QUIC**, **Sing-box / Xray / Happ JSON subscriptions**).

It ships as both:
1. **Native Windows Desktop Application (`/desktop-cs/NetworkChecker.slnx`)** built on **.NET 10**, **C# 14**, **Avalonia UI 12.1.4**, and **CommunityToolkit.Mvvm 8.4.2** with `TreatWarningsAsErrors=true` and zero reflection (`ViewLocator` compatible with `PublishSingleFile` / NativeAOT).
2. **Interactive Web Workbench** (React 19 + TypeScript + Express backend) that mirrors the 6 diagnostic tabs and packages the entire C# Desktop solution into a one-click downloadable `NetworkChecker-V2-CSharp-Desktop.zip`.

![Tab 5 — IP Reputation & Google RU Geo-Poisoning Inspector](./screenshots/05-ip-reputation-google-ru.svg)

---

## Key Capabilities (6 Diagnostic Modules)

| Tab | Module | What It Audits & Fixes |
| :--- | :--- | :--- |
| **Step 1** | **VPN & Subscription Auditor** | Auto-detects `https://` subscription URLs, **Happ / Xray JSON balancer arrays**, Base64 lists, `vless://`, `hy2://`, `trojan://`, `vmess://`, `ss://`, and **AmneziaWG**. Injects clean DNS & SNI into every node and hosts a local subscription URL (`http://127.0.0.1:17890/sub/...`). |
| **Step 2** | **DNS Protection & JSON Architect** | Live DNS spoofing comparison (System ISP DNS vs encrypted DoH). Generates **Classic DoH (`Cloudflare 1.1.1.1 + Google 8.8.8.8`)** and **Privacy Ninja (`Njalla + LibreDNS + Quad9 + Mullvad`)** with `.RU` split routing (`77.88.8.8`), validating strict JSON syntax (`JsonDocument.Parse`) on every injection. |
| **Step 3** | **TSPU & 16 KB Block Scanner** | Detects the **16 KB TCP connection cap** on foreign cloud ASNs (Hetzner, OVH, Cloudflare, DigitalOcean), TLS certificate MITM replacement, UDP / STUN (`RFC 5389`) voice call blocking, and mobile **"Whitelist Mode"** lockdowns. |
| **Step 4** | **Windows Network Stack & Reality SNI Hunter** | Native L3 audit of **Wintun / Sing-box TUN** adapters, MTU, outside-TUN DNS leaks (SMHNR), and global IPv6 (`2000::/3`) leaks. Includes a **raw RFC 8446 TLS 1.3 ClientHello SNI probe** that verifies real `0x0304` negotiation, `X25519` key share, `h2` ALPN, and rejects servers triggering `HelloRetryRequest`. |
| **Step 5** | **IP Reputation & Google `RU` Inspector** | **4-Provider GeoIP Consensus** (`ipwho.is`, `ip-api.com`, `ipinfo.io`, `Cloudflare Trace` — **Majority Vote `>=50%`** for `Hosting`, **Any Vote** for `Proxy/VPN`), live **Google / YouTube `INNERTUBE_CONTEXT_GL` & `/sorry/` probe** to detect foreign VPN IPs poisoned with Google's `RU` region tag, plus a **Batch Subscription IP Scanner** that extracts and audits all server IPs inside your subscription. |
| **Step 6** | **2-Step Support Ticket Builder** | Captures comparative snapshots (**Step 1: Without VPN** vs **Step 2: With VPN**), supports multi-select internet symptoms, omits specific single-node details, and masks all private keys (`UUID`, `pbk`, home IP). |

---

## Visual Tour of All 6 Tabs

### 1. VPN & Subscription Auditor (`Happ / Xray JSON / VLESS / AmneziaWG / Hysteria2`)
![Tab 1 — VPN & Subscription Auditor](./screenshots/01-config-audit-subscriptions.svg)

### 2. DNS Protection & Strict JSON Injection (`Classic DoH` & `Privacy Ninja`)
![Tab 2 — DNS Architect](./screenshots/02-dns-architect-injection.svg)

### 3. TSPU Fingerprints & 16 KB TCP Cap Scanner
![Tab 3 — TSPU Fingerprints](./screenshots/03-tspu-fingerprints-16kb.svg)

### 4. Windows Network Stack & Raw RFC 8446 TLS 1.3 Reality SNI Hunter
![Tab 4 — Windows Stack & SNI Hunter](./screenshots/04-windows-stack-sni-hunter.svg)

### 5. IP Reputation, Google `RU` Geo-Poisoning Detector & Batch Subscription IP Scanner
![Tab 5 — IP Reputation & Google RU Inspector](./screenshots/05-ip-reputation-google-ru.svg)

### 6. 2-Step Support Ticket Generator (Multi-Select Symptoms & Secret Redaction)
![Tab 6 — Support Ticket Builder](./screenshots/06-support-ticket-generator.svg)

---

## Architecture & Build Instructions (C# Desktop `.NET 10`)

```text
desktop-cs/
├── NetworkChecker.slnx
├── Directory.Build.props                # .NET 10, C# 14, Nullable, TreatWarningsAsErrors=true
├── screenshots/                         # Visual SVG previews of all 6 tabs
├── src/
│   ├── NetworkChecker.Core/             # Pure diagnostic & protocol engine
│   │   └── VpnAudit/
│   │       ├── VpnConfigParser.cs       # Happ JSON arrays, VLESS, HY2, AWG, Base64
│   │       ├── VpnConfigAuditor.cs      # RF-focused security & DPI resistance rules
│   │       ├── DnsConfigArchitect.cs    # Classic DoH + Privacy Ninja + strict JSON AST patcher
│   │       ├── TspuBlockingScanner.cs   # 16 KB TCP cap, TLS MITM, STUN RFC 5389, Whitelist mode
│   │       ├── WindowsNetworkStackAuditor.cs # TUN/Wintun, MTU, SMHNR DNS, IPv6 2000::/3, proxy ports
│   │       ├── SniHunterProbe.cs        # Raw RFC 8446 TLS 1.3 ClientHello + ServerHello parser
│   │       ├── IpReputationProbe.cs     # 4-provider GeoIP consensus, Google GL=RU probe, batch IP scanner
│   │       ├── RttBenchmarkProbe.cs     # Multi-sample TCP RTT, Jitter, P95, loss
│   │       ├── SubscriptionService.cs   # Subscription fetcher, bulk patcher & local loopback host
│   │       └── SupportTicketBuilder.cs  # 2-step comparative support report generator
│   └── NetworkChecker.App/              # Avalonia 12.1.4 MVVM Desktop UI
│       ├── ViewModels/                  # 6 Tab ViewModels + MainWindowViewModel
│       └── Views/                       # Compiled AXAML Views + adaptive DPI MainWindow
└── tests/
    └── NetworkChecker.Core.Tests/       # xUnit test suite covering all parsers, probes & patchers
```

### Build & Run on Windows / Linux / macOS

```bash
cd desktop-cs
dotnet test NetworkChecker.slnx
dotnet run --project src/NetworkChecker.App/NetworkChecker.App.csproj
```

### Publish Standalone Single-File Windows `.exe`

```bash
cd desktop-cs
dotnet publish src/NetworkChecker.App/NetworkChecker.App.csproj \
  -c Release -r win-x64 --self-contained true \
  -p:PublishSingleFile=true \
  -p:IncludeNativeLibrariesForSelfExtract=true
```

---

## Detailed Russian Documentation

For a full walkthrough of every diagnostic check, Google `RU` geo-poisoning detection mechanics, and JSON subscription patching, read **[README.ru.md](./README.ru.md)**.
