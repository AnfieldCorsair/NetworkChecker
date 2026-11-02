using NetworkChecker.Core.Models;
using NetworkChecker.Core.Options;

namespace NetworkChecker.Core.Verdict;

/// <summary>
/// Матрица соответствия прогона опубликованной трёхэтапной методике выявления средств
/// обхода (серверный этап → мобильные устройства → десктопы). Строится только из уже
/// собранных <see cref="CheckResult"/>: никаких новых сетевых запросов и обращений к ОС.
///
/// ВАЖНО: документ-первоисточник официально не подтверждён, а реальные правила площадок
/// неизвестны. Это модель для самопроверки, не решение сайта, РКН или оператора и не
/// вероятность использования VPN.
/// </summary>
public static class MethodologyMatrix
{
    private const string Server = "Сервер (этап 1)";
    private const string Device = "Устройство Windows (этап 3)";
    private const string Mobile = "Мобильное устройство (этап 2)";

    public static MethodologyAssessment Build(IReadOnlyList<CheckResult> checks, IpConsensus consensus)
    {
        ArgumentNullException.ThrowIfNull(checks);
        ArgumentNullException.ThrowIfNull(consensus);

        var signals = new List<MethodologySignal>();

        CheckResult? Find(CheckCategory category) => checks.FirstOrDefault(c => c.Category == category);

        MethodologySignalState State(CheckCategory category, Func<Finding, bool> present, Func<Finding, bool>? unknown = null)
        {
            var check = Find(category);
            if (check is null || check.Status is CheckStatus.Skipped or CheckStatus.Failed) return MethodologySignalState.Unknown;
            if (unknown is not null && check.Findings.Any(unknown)) return MethodologySignalState.Unknown;
            return check.Findings.Any(present) ? MethodologySignalState.Present : MethodologySignalState.Absent;
        }

        static MethodologySignalState Combine(params MethodologySignalState[] states)
        {
            if (states.Any(s => s == MethodologySignalState.Present)) return MethodologySignalState.Present;
            return states.All(s => s == MethodologySignalState.Unknown)
                ? MethodologySignalState.Unknown
                : MethodologySignalState.Absent;
        }

        static bool Has(Finding f, string part) => f.Title.Contains(part, StringComparison.OrdinalIgnoreCase);

        Func<Finding, bool> geoUnknown = f => Has(f, "Данные GeoIP неполные");

        signals.Add(new MethodologySignal(Server, "Метка VPN / прокси / Tor в репутационных базах",
            State(CheckCategory.GeoIp, f => Has(f, "IP помечен") || Has(f, "proxy/VPN/Tor"), geoUnknown),
            "РАНР, MaxMind, IP2Location и списки выходных узлов Tor доступны только серверу; здесь — ответы публичных GeoIP."));
        signals.Add(new MethodologySignal(Server, "Хостинг / ASN дата-центра",
            State(CheckCategory.GeoIp, f => Has(f, "хостинг") || Has(f, "дата-центру"), geoUnknown),
            "Метка hosting зависит от базы и может быть ошибочной."));
        signals.Add(new MethodologySignal(Server, "Иностранный адрес выхода",
            State(CheckCategory.GeoIp, f => Has(f, "не российский"), geoUnknown),
            "Сам по себе зарубежный адрес не считается обходом: возможны поездка, роуминг и CDN."));
        signals.Add(new MethodologySignal(Server, "Заголовки X-Forwarded-For / Forwarded / Via",
            State(CheckCategory.CdnPulling, f => Has(f, "прокси-заголовки")),
            "Эхо-сервис показывает заголовки зонда приложения, а не браузера; CDN добавляет их легитимно."));
        signals.Add(new MethodologySignal(Server, "Аномалия RTT / SNITCH",
            State(CheckCategory.RttTriangulation, f => Has(f, "медленнее")),
            "Клиентская оценка задержек; серверный SNITCH сравнивает RTT с географией IP."));
        signals.Add(new MethodologySignal(Server, "Расщепление внешних адресов / корреляция потоков",
            consensus.ConsensusIp is null
                ? MethodologySignalState.Unknown
                : consensus.IsSplit ? MethodologySignalState.Present : MethodologySignalState.Absent,
            "Сравниваются адреса одного семейства; netflow-корреляция оператора локально недоступна."));
        signals.Add(new MethodologySignal(Server, "DNS-утечка или расхождение ответов DNS/DoH",
            State(CheckCategory.TransportObservation,
                f => Has(f, "DNS-резолвер отличается") || Has(f, "вернули разные адреса")),
            "Наблюдательный модуль: whoami-имена и публичный DoH, без DNSSEC."));

        signals.Add(new MethodologySignal(Device, "Настроенный системный прокси / PAC",
            State(CheckCategory.DirectSigns, f => f.Kind == EvidenceKind.ConfiguredProxy),
            "WinINET / WinHTTP / переменные окружения / PAC; не подтверждает маршрут браузера."));
        signals.Add(new MethodologySignal(Device, "Подключённый VPN-профиль ОС (RAS)",
            State(CheckCategory.DirectSigns, f => f.Kind == EvidenceKind.ConnectedWindowsVpn),
            "Эквивалент RasEnumConnection / Get-VpnConnection."));
        signals.Add(new MethodologySignal(Device, "Туннельные и VPN-подобные интерфейсы",
            Combine(
                State(CheckCategory.DirectSigns, f => Has(f, "туннельный интерфейс")),
                State(CheckCategory.IndirectSigns, f => Has(f, "VPN-подобным именем"))),
            "Имена tun/tap/wg/utun/ppp и тип интерфейса; виртуализация даёт ложные срабатывания."));
        signals.Add(new MethodologySignal(Device, "Маршруты: default через туннель и host route /32",
            State(CheckCategory.IndirectSigns, f => Has(f, "маршрут") || Has(f, "Хостовые")),
            "Get-NetRoute / таблица маршрутизации; отдельные приложения могут идти иначе."));
        signals.Add(new MethodologySignal(Device, "DNS, NRPT, MTU, hosts",
            State(CheckCategory.IndirectSigns,
                f => Has(f, "DNS") || Has(f, "MTU") || Has(f, "hosts") || Has(f, "NRPT")),
            "Типовые значения MTU 1350/1400/1420 не идентифицируют клиент."));
        signals.Add(new MethodologySignal(Device, "Локальные прокси-порты и API клиентов",
            State(CheckCategory.Bypass, f => Has(f, "Возможный локальный") || Has(f, "Ответ версии")),
            "Настроенные порты, диапазоны методики и TCP LISTEN; ответ ≠ использование браузером."));
        signals.Add(new MethodologySignal(Device, "Установленные клиенты, процессы, службы",
            State(CheckCategory.DirectSigns,
                f => Has(f, "Установлены клиенты") || Has(f, "Запущен процесс") || Has(f, "Служба туннеля")),
            "Реестр Uninstall и список процессов; сам факт установки ничего не доказывает."));
        signals.Add(new MethodologySignal(Device, "Kill switch / правила файрвола",
            State(CheckCategory.DirectSigns, f => Has(f, "kill switch")),
            "Исходящие блокировки, связанные с VPN-клиентом."));
        signals.Add(new MethodologySignal(Device, "UDP / STUN и расхождение TCP/UDP",
            State(CheckCategory.CallTransport, f => Has(f, "разные адреса")),
            "Отсутствие STUN-ответа не означает отсутствие всего UDP."));

        signals.Add(new MethodologySignal(Mobile, "Android/iOS: TRANSPORT_VPN, dumpsys, CFNetwork",
            MethodologySignalState.Unknown,
            "Не применимо: приложение работает на Windows и не читает API мобильных ОС. " +
            "Именно на Android/iOS, по оценке методики, приходится около 80% клиентских проверок."));

        var serverSignals = signals.Where(s => s.Stage == Server).ToList();
        var deviceSignals = signals.Where(s => s.Stage == Device).ToList();
        var hasServer = serverSignals.Any(s => s.State == MethodologySignalState.Present);
        var hasDevice = deviceSignals.Any(s => s.State == MethodologySignalState.Present);
        var missing = checks.Any(c => c.Weight > 0 && c.Status is CheckStatus.Skipped or CheckStatus.Failed)
                      || serverSignals.All(s => s.State == MethodologySignalState.Unknown)
                      || deviceSignals.All(s => s.State == MethodologySignalState.Unknown);

        string decision;
        string explanation;
        if (missing)
        {
            decision = "Данных недостаточно для вывода по матрице";
            explanation = "Часть модулей не отработала или источники не вернули сведений. " +
                          "Отсутствующие и пропущенные проверки не превращаются в чистый результат.";
        }
        else if (hasServer && hasDevice)
        {
            decision = "По матрице: совпали серверный и клиентский сигналы";
            explanation = "Такой набор признаков методика считает основанием для вывода об обходе. " +
                          "Здесь это только модель по собранным наблюдениям: каждый сигнал может иметь другое объяснение.";
        }
        else if (hasServer || hasDevice)
        {
            decision = "По матрице: одного сигнала недостаточно, требуется уточнение";
            explanation = "Методика прямо оговаривает: один положительный сигнал на устройстве " +
                          "без серверного подтверждения не является решением.";
        }
        else
        {
            decision = "По матрице: значимых сигналов в доступных данных нет";
            explanation = "Это не исключает VPN на роутере, резидентный прокси, split tunneling, " +
                          "новый сервис или ошибку репутационной базы.";
        }

        explanation += " Матрица не воспроизводит алгоритмы конкретного сайта, РКН или оператора; " +
                       "первоисточник методики официально не подтверждён.";

        return new MethodologyAssessment(
            signals,
            decision,
            explanation,
            hasServer,
            hasDevice,
            missing,
            hasServer && !hasDevice && !missing,
            [.. FalsePositiveCatalog.ContextNotes],
            NotMeasurable());
    }

    private static IReadOnlyList<string> NotMeasurable() =>
    [
        "Активное зондирование VPN-серверов, сигнатуры протоколов и кэш классификации ТСПУ находятся на стороне оператора; ПК видит только последствия (RST, паузу, дросселирование).",
        "TLS-отпечатки JA3/JA4 и ECH: нужен настоящий браузерный TLS-стек; зонд приложения его не воспроизводит.",
        "Пассивный TCP/IP fingerprint (MSS, TTL, окно) и MTU-сигнатура в SYN со стороны сервера.",
        "WebRTC-, IPv6- и браузерные DNS-утечки, язык и часовой пояс именно браузера, а не системы.",
        "Список приложений на других устройствах, GPS, MCC/PLMN, BSSID и данные сотовой сети.",
        "СОРМ, серверные логи площадок, реестр РАНР, белые списки РКН и решения конкретных сервисов.",
    ];
}
