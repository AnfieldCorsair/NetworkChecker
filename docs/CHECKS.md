# Справочник проверок

Для каждого модуля: что читает, как принимает решение, какой вес даёт в вердикте и что означает результат. Уровни находок: `Info` (контекст), `Notice` (косвенно), `Warning` (сильный сигнал), `Critical` (прямой признак).

---

## 1. GeoIP и репутация IP — `GeoIpCheck`, вес 20

**Читает:** `api.ipapi.is`, `iplocate.io`, `ipinfo.io`, `myip.com` (список редактируется в настройках).

**Логика:**
- `hosting` — majority vote среди провайдеров, вернувших это поле;
- `proxy/VPN/Tor` — достаточно одного совместимого ответа;
- страна — сначала из основного источника, при отсутствии — из первого ответившего.

| Ситуация | Статус | Находка |
|---|---|---|
| `proxy/hosting = true` | `Detected` | `Critical` / `Warning` |
| иностранный IP без hosting/proxy | `NeedsReview` | `Notice` |
| российский IP без меток | `Clean` | `Info` |
| провайдеры расходятся в стране | `Detected` | `Notice` о расхождении баз |
| никто не ответил | `Failed` | — |

Найденный IP уходит в общий консенсус (`CollectIp`) с флагом «российский/иностранный».

---

## 2. Сравнение IP-источников — `IpComparisonCheck`, вес 0

**Читает:** `ipify`, `myip.com`, `ipapi.is`, `cloudflare/cdn-cgi/trace`, STUN (UDP).

**Логика:** собирает адреса по разным путям и сравнивает.

- один адрес у всех → `Clean`, `Info`;
- разные адреса → `Detected`, `Warning` (split tunneling / цепочка прокси);
- отдельно ловится случай «HTTP видит один адрес, STUN — другой»: прокси перехватывает только TCP.

Вес 0: в вердикт напрямую не входит, питает консенсус и служит диагностикой.

---

## 3. Прямые признаки — `DirectSignsCheck`, вес 30

| Что | Источник | Уровень |
|---|---|---|
| Системный прокси | `HKCU\...\Internet Settings` (`ProxyEnable`, `ProxyServer`, `AutoConfigURL`, `ProxyOverride`), машинные `DefaultConnectionSettings`, `HTTP_PROXY`/`ALL_PROXY` | `Critical` |
| TUN/TAP-адаптер Up | `NetworkInterface` (тип `Tunnel` + имена `tun/tap/wg/wintun/nordlynx/clash…`) | `Critical` |
| Активное VPN-подключение ОС | `Get-VpnConnection` (все пользователи + текущий) | `Critical` |
| Запущенный клиент обхода | процессы сверяются с каталогом из 38 маркеров | `Critical` |
| Установленный клиент | три ветки `Uninstall` в реестре | `Warning` |
| Запущенная служба туннеля | `Get-Service` + `SYSTEM\...\Services` | `Warning` |
| Kill switch | `Get-NetFirewallRule` (outbound/block) + имя приложения из каталога | `Warning` |

Каталог клиентов: WireGuard, OpenVPN, Amnezia, Outline, NordVPN, Proton, ExpressVPN, Surfshark, Windscribe, Mullvad, WARP, AdGuard VPN, SoftEther, v2rayN, Xray, Shadowsocks, NekoRay, Clash/Mihomo, sing-box, Hiddify, Lantern, Psiphon, Tor, GoodbyeDPI, zapret/winws, SpoofDPI, ByeDPI, Green Tunnel, Netch, SSTap, tun2socks и драйверы TAP/Wintun/ovpn-dco.

---

## 4. Косвенные признаки — `IndirectSignsCheck`, вес 20

- **VPN-подобное имя интерфейса** → `Critical`.
- **MTU туннеля ≠ 1500/1420** → `Notice` (выдаёт клиента: 1280, 1300, 9000…).
- **Default route через туннельный интерфейс** → `Critical` (перехват всего трафика).
- **Хостовые маршруты /32** → `Notice` (типовой приём tun2socks).
- **DNS на loopback** → `Critical`; **приватный DNS** → `Notice`; **DNS туннеля перекрывает системный** → `Warning`.
- **NRPT-политики (split DNS)** → `Notice`.
- **Нестандартные записи hosts** (всё, кроме `localhost`, `::1`, `127.0.0.1`, `*.local`) → `Notice`.
- **Активные виртуальные адаптеры** → `Notice`.

---

## 5. Локальный обход — `BypassCheck`, вес 30

**Порты:** 1080, 1081, 1087, 1088, 2080, 3128, 7890, 7891, 7897, 8080, 8081, 8888, 9050, 9051, 9090, 9091, 10808, 10809, 20170, 20171.

**Методы идентификации:** SOCKS5-приветствие (`05 01 00`), `CONNECT` к `example.com:443` для HTTP-прокси, чтение баннера для прочих сервисов.

**Дополнительно:** Xray API (`127.0.0.1:10085`), Clash/Mihomo external controller (`:9090`, `:9091`, эндпоинт `/version`), эвристика «SOCKS5 + TUN».

Любой ответивший локальный прокси → `Critical`. Связка SOCKS5 + туннель → `Notice`.

---

## 6. UDP / STUN-транспорт — `CallTransportCheck`, вес 10

- Binding-запрос к STUN-серверам (`stun.l.google.com`, `stun.cloudflare.com`, `stun.sipnet.ru`).
- Ни один не ответил → `Warning`: UDP блокируется или прокси заворачивает только TCP.
- Разные порты у одного узла → `Notice` (симметричный NAT); разные адреса → `Warning`.
- **UDP-адрес ≠ HTTPS-адрес** → `Critical`: классическая утечка при TCP-only прокси.
- MTProto-проба Telegram DC (`149.154.167.51:443`) — справочная метрика доступности.

---

## 7. CDN и redirector — `CdnPullingCheck`, вес 5

`cdn-cgi/trace` (ip, loc, colo) и `httpbin/headers`. Ловит:
- страну выхода, отличную от RU → `Notice`;
- прокси-заголовки `Via`, `X-Forwarded-For`, `Forwarded`, `Proxy-Connection`, `X-Real-Ip` → `Critical`.

---

## 8. Доступность доменов — `DomainReachabilityCheck`, вес 10

Для каждого домена из списка: DNS → TCP :443 → TLS.

| Этап | Что означает |
|---|---|
| DNS не резолвит | блокировка/подмена на уровне DNS → `Warning` |
| TCP не открывается | DPI по SNI/IP → `Notice` |
| TLS не поднимается | сброс по SNI или MITM → `Notice` |
| сертификат от неизвестного CA | перехват TLS → `Warning`, статус `Detected` |

Все домены доступны → `Info`: если VPN включён, заметного выигрыша по этим целям он не даёт.

---

## 9. RTT-триангуляция (β) — `RttTriangulationCheck`, вес 15

Замеры до RU-хостов (`ya.ru`, `mail.ru`, `vk.com`, `gosuslugi.ru`) и иностранных (`1.1.1.1`, `8.8.8.8`, `9.9.9.9`, `cloudflare.com`).

- Сначала ICMP (`Ping`), при блокировке — TCP :443/:80, метод попадает в метрики.
- Медиана RU − медиана «мир» > 60 мс → `Warning`: похоже, российский трафик уходит за границу и возвращается.
- Разница в пределах ±60 мс → `Info`: маршруты симметричны.
- Потери до «мира» > 30 % при низких потерях до RU → `Notice` (может быть фильтрация ICMP).
- Jitter > 80 мс → `Notice`.

---

## 10. ICMP-спуфинг (β) — `IcmpSpoofingCheck`, вес 10

Для каждого хоста из `IcmpSpoofTargets` сравниваются ICMP-эхо и TCP :443.

| Наблюдение | Уровень |
|---|---|
| ICMP отвечает, TCP :443 — нет | `Warning` (фильтрация по порту или подделка ICMP) |
| ICMP и TCP отвечают с **разных** адресов | `Critical` (прозрачный перехват) |
| TCP открыт, TLS не поднялся | `Notice` (сброс по SNI) |
| ICMP с TTL < 40 и RTT < 3 мс | `Warning` (ответ локального перехватчика, а не зарубежного сервера) |

---

## Вердикт

```text
score = Σ(вес × коэффициент_категории × серьёзность) / Σ(вес × коэффициент_категории) × 100
```

Коэффициенты категорий: прямые признаки 1.0, локальный обход 1.0, GeoIP 0.7, косвенные 0.6, UDP/STUN 0.5, RTT 0.4, ICMP 0.4, домены 0.25, CDN 0.2. Серьёзность: `Detected`+`Critical` = 1.0, `Detected` = 0.8, `NeedsReview` = 0.45, `Clean` = 0.

Правила поверх балла:

| Условие | Вердикт |
|---|---|
| прямой `Critical` **и** (GeoIP `Detected` или локальный обход `Critical` или расщепление IP) | **Обнаружен обход** (минимум 80) |
| прямой `Critical` / локальный обход `Critical` / балл ≥ 60 / GeoIP `Detected` + раскол IP | **Обнаружен обход** (минимум 60) |
| балл ≥ 25 или есть триггеры, или IP расходятся | **Требует проверки** (минимум 30) |
| иначе | **Чисто** |

Если часть модулей упала, к резюме добавляется «вердикт неполный».
