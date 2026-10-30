# NetworkChecker

**Windows network diagnostics, from a readable overview to detailed evidence.**  
Version 1.6.5 · [Русский](README.ru.md) · [Home](README.md)

NetworkChecker explores network configuration, connectivity and indicators that can be consistent with VPNs, proxies or tunnelling. It started as a PC adaptation inspired by [RKNHardering](https://github.com/xtclovver/RKNHardering) and continues to develop beyond that starting point. Thanks to its authors and contributors for the inspiration.

> **The 0–100 index is a heuristic, not a probability or proof.** A proxy configuration or connected Windows VPN profile is not proof of a browser's actual route. Missing and failed checks do not count as clean results. No screen represents a real decision by a particular website.

## Two ways to explore

- **Simple:** a plain-language verdict and a small set of network facts.
- **Detailed:** checks, metrics, findings, adapters, routes, DNS, connectivity diagnostics and a hop-by-hop trace.
- **Website perspective:** a model based on a GeoIP response and local system information, not a view of what a particular browser or site actually sees. Its separate score is also heuristic.
- **History:** local SQLite storage and comparison of runs. Differences can reflect missing data or changed conditions, not a change in security.
- **Guide:** explanations of checks, data and limitations.

![Simple dashboard](screenshots/02-dashboard-simple-result.png)

Screenshots show the earlier 1.6 interface; some wording and window layout have since changed. The [trace illustration](screenshots/07b-network-trace-demo.png) uses synthetic data.

## Checks and limitations

The checks combine GeoIP sources, HTTP and STUN address comparison, Windows proxy/VPN configuration, routing and DNS clues, local proxy port probes, transport and domain reachability, RTT comparisons and experimental ICMP spoofing indicators. Results are subject to timeouts, unavailable services, local policy and false positives. A traceroute timeout does not prove a broken path; ASN lookups use Team Cymru and may be missing or outdated.

**Privacy:** private export and new history entries reduce identifiable data; they do not anonymize network requests, clear old history or guarantee that every on-screen field is hidden. Reports and captures can still contain sensitive data. Review them before sharing.

**Language:** choose `ru-RU` or `en-US` in Settings, save, and restart. The app does not change the operating system culture. English coverage is incomplete: some dynamic findings, stored results, third-party/system errors and report contents can remain in Russian.

## Check modules

| Module | Purpose | Weight |
|---|---|---:|
| GeoIP and reputation | Multiple providers and their hosting/proxy labels | 20 |
| Address comparison | Compare HTTP, CDN and STUN observations | 0 |
| Direct indicators | Windows proxy settings, PAC, tunnel interfaces, VPN profiles and local clients | 30 |
| Indirect indicators | Routes, DNS/NRPT, MTU, hosts and virtual adapters | 20 |
| Local proxy probes | Inspect configured loopback ports and supported protocol responses | 30 |
| UDP / STUN transport | STUN binding and TCP/UDP egress comparison | 10 |
| CDN and redirectors | Edge information and proxy-related headers | 5 |
| Domain reachability | DNS → TCP → TLS diagnostics | 10 |
| RTT comparison (experimental) | ICMP and TCP measurements, without locating the actual route | 15 |
| ICMP spoofing indicators (experimental) | Compare responses; a signal alone does not prove spoofing | 10 |

The score excludes failed or skipped checks from its denominator. When there is insufficient weighted data, the score is not calculated. The system does not assert that a particular browser uses a detected route. [Detailed methodology and caveats](docs/CHECKS.md) are currently in Russian.

## Diagnostics and trace

The Network tab offers an overview, diagnostics and a hop sequence. IPv4/IPv6 observations are compared within the same family; different addresses do not, by themselves, establish split tunnelling. Trace colors group ASNs but can collide; gray indicates an unknown ASN. Team Cymru DNS queries are sent for hop addresses. RTT is available only when the probing method provides it, and a timeout does not establish a broken connection.

## Local storage and permissions

Data is stored under `%LOCALAPPDATA%\NetworkChecker\`: `settings.json`, SQLite `history.db`, and Serilog files in `logs\`. The application has no project-operated server, but online checks contact third-party services. Offline mode disables external probes while retaining local checks.

Administrator rights are not required for the basic workflow, though some sources may be unavailable or incomplete. WFP/ETW observation and raw ICMP may require additional rights. Elevation is optional, requested only through the relevant user action; observation is not started automatically. See [administrator notes](docs/ADMIN.md) and [observation limitations](docs/OBSERVATION.md).

## Packet files and experimental observation

- The capture tab reads local **PCAP and some PCAPNG** files, up to 32 MiB and 2,000 packets, with basic Ethernet/IPv4/IPv6 decoding and the first 256 bytes of a selected frame. Unsupported blocks and protocols are limited. This is **not live capture**; HTTPS is not decrypted.
- WFP/ETW observation is experimental and starts only with explicit user action. Optional elevation is offered; UAC is never triggered automatically. It captures limited WFP information and TCPIP events, not packet contents, and does not modify filters. It is not an interception detector. See [observation notes](docs/OBSERVATION.md).

Planned work includes live packet capture with explicit start/stop, bounded capture and log autosave, a small metadata log while the app is open, separate monitoring while its tab is open, fuller localization, and Windows validation. No live backend has been finalized.

## Reports

Export to PDF, DOCX, XLSX, CSV, Markdown, JSON or standalone HTML. [Sample reports](samples/) demonstrate the formats; they were generated by an earlier version and may not reflect the latest behavior. CSV and Markdown headings and known fields can be presented in English; other report formats and unknown dynamic contents may still contain Russian text when English is selected. Review third-party licensing conditions, including QuestPDF Community terms, before distributing builds.

## Build on Windows

Install the **.NET 10 SDK**, open PowerShell in the source folder, and run:

```powershell
./build.ps1 -Publish
```

The script restores dependencies, builds, runs tests and publishes to `artifacts/win-x64`. For manual steps:

```powershell
dotnet restore
dotnet build
dotnet test
dotnet run --project src/NetworkChecker.App
```

See the detailed [beginner's build guide](docs/BUILD.md) (Russian), [architecture](docs/ARCHITECTURE.md), [checks](docs/CHECKS.md), [limitations](docs/REVIEW.md), and [changelog](CHANGELOG.md). The application targets Windows; portable automated tests do not prove Windows-specific behavior.

## Solution and testing

```text
src/NetworkChecker.Core             checks, models, verdict, network tools, capture reader
src/NetworkChecker.Platform.Windows Windows-specific sources and experimental observation
src/NetworkChecker.Data             SQLite history and settings
src/NetworkChecker.Export           report formats
src/NetworkChecker.App              Avalonia desktop UI
tests/                              core, data, export and headless UI tests
tools/NetworkChecker.Screenshots    headless UI screenshot generator
```

A run goes from the dashboard through `CheckRunner` and the registered checks to the verdict and IP-consensus builders, then to local history and the UI/export. The test projects cover core checks and parsers, the storage layer, all export formats, view models and headless rendering. Some Windows-specific behavior still requires validation on Windows; Linux-hosted tests alone do not prove it.

More screenshots: [detailed results](screenshots/03-dashboard-pro-result.png), [network diagnostics](screenshots/06-network-diagnostics.png), [history](screenshots/08-history.png), [website model](screenshots/10-site-view.png), [guide](screenshots/11-guide.png), [settings](screenshots/12-settings.png), and [observation tab](screenshots/13-observation.png). The [observation example](screenshots/13b-observation-demo.png) contains synthetic data.

## Technology

.NET 10, Avalonia, CommunityToolkit.Mvvm, EF Core/SQLite, Microsoft.Extensions.Hosting, Serilog and TraceEvent. The solution separates core checks, Windows platform access, storage, export and the desktop application. Automated tests cover these layers.

## Licence and acknowledgements

Copyright © 2026 AnfieldCorsair. [AGPL-3.0-only](LICENSE); no warranty. [Source repository](https://github.com/AnfieldCorsair/NetworkChecker). Third-party components have their own terms; the bundled DejaVu font licence is in [third-party/DejaVu-LICENSE.txt](third-party/DejaVu-LICENSE.txt). RKNHardering was a source of inspiration; thanks to its authors and contributors.
