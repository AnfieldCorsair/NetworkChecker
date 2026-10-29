using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using NetworkChecker.Core.Observation;

namespace NetworkChecker.Platform.Windows;

/// <summary>WFP и ETW: только чтение/подписка, без изменения фильтров и без пакетов.</summary>
public sealed class WindowsObservationService : IObservationService
{
    public async Task<ObservationReport> ObserveAsync(TimeSpan duration, CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
        {
            var unavailable = new ObservationPart("Windows", false, "Доступно только в Windows", [], 0);
            return new ObservationReport(unavailable with { Source = "WFP" }, unavailable with { Source = "ETW" });
        }

        duration = TimeSpan.FromSeconds(Math.Clamp(duration.TotalSeconds, 1, 60));
        var wfp = Task.Run(() => ObserveWfpAsync(duration, cancellationToken), CancellationToken.None);
        var etw = Task.Run(() => ObserveEtwAsync(duration, cancellationToken), CancellationToken.None);
        return new ObservationReport(await wfp.ConfigureAwait(false), await etw.ConfigureAwait(false));
    }

    private static async Task<ObservationPart> ObserveWfpAsync(TimeSpan duration, CancellationToken ct)
    {
        var buffer = new ObservationBuffer(250);
        IntPtr engine = IntPtr.Zero, subscription = IntPtr.Zero;
        Native.FilterCallback? callback = null;
        WfpSnapshot? snapshot = null;
        try
        {
            Check(Native.EngineOpen(null, 10, IntPtr.Zero, IntPtr.Zero, out engine), "FwpmEngineOpen0");
            callback = (_, changePtr) =>
            {
                try
                {
                    var change = Marshal.PtrToStructure<Native.FilterChange>(changePtr);
                    var kind = change.Type switch { 1 => "Добавлен", 2 => "Удалён", _ => "Изменение" };
                    buffer.Add(new ObservationEvent("WFP", kind, $"Filter {change.Key:D} · ID {change.Id.ToString(CultureInfo.InvariantCulture)}", DateTimeOffset.Now));
                }
                catch { /* Нельзя допустить исключение через границу native callback. */ }
            };
            var options = new Native.FilterSubscription { Flags = 3 };
            string? subscriptionError = null;
            try { Check(Native.Subscribe(engine, ref options, callback, IntPtr.Zero, out subscription), "FwpmFilterSubscribeChanges0"); }
            catch (InvalidOperationException ex) { subscriptionError = ex.Message; }
            var observationStarted = System.Diagnostics.Stopwatch.StartNew();
            snapshot = ReadWfpSnapshot(engine, ct);
            if (subscriptionError is not null)
                return new ObservationPart("WFP", false, subscriptionError, [], 0) { Snapshot = snapshot };
            var remaining = duration - observationStarted.Elapsed;
            if (remaining > TimeSpan.Zero) await Task.Delay(remaining, ct).ConfigureAwait(false);
            var result = buffer.Snapshot();
            return new ObservationPart("WFP", true, "Подписка выполнена; изменения видны только во время наблюдения.", result.Events, result.Dropped) { Snapshot = snapshot };
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            var result = buffer.Snapshot();
            return new ObservationPart("WFP", true, "Наблюдение остановлено пользователем.", result.Events, result.Dropped) { Snapshot = snapshot };
        }
        catch (Exception ex)
        {
            var result = buffer.Snapshot();
            return new ObservationPart("WFP", false, ex.GetBaseException().Message, result.Events, result.Dropped) { Snapshot = snapshot };
        }
        finally
        {
            if (subscription != IntPtr.Zero) _ = Native.Unsubscribe(engine, subscription);
            if (engine != IntPtr.Zero) _ = Native.EngineClose(engine);
            GC.KeepAlive(callback);
        }
    }

    // Один ограниченный снимок после подписки; это не периодический опрос.
    private static WfpSnapshot ReadWfpSnapshot(IntPtr engine, CancellationToken ct)
    {
        const int maxScanned = 10000, maxShown = 250, pageSize = 256;
        var filters = new List<WfpFilterRecord>();
        var callouts = new List<WfpFilterRecord>();
        var calloutCount = 0;
        IntPtr enumerator = IntPtr.Zero;
        var scanned = 0;
        var truncated = false;
        try
        {
            Check(Native.CreateEnum(engine, IntPtr.Zero, out enumerator), "FwpmFilterCreateEnumHandle0");
            while (scanned < maxScanned)
            {
                ct.ThrowIfCancellationRequested();
                var entries = IntPtr.Zero;
                try
                {
                    var request = (uint)Math.Min(pageSize, maxScanned - scanned);
                    Check(Native.EnumFilters(engine, enumerator, request, out entries, out var count), "FwpmFilterEnum0");
                    for (var i = 0; i < count; i++)
                    {
                        var pointer = Marshal.ReadIntPtr(entries, checked((int)i * IntPtr.Size));
                        var item = Marshal.PtrToStructure<Native.FilterPrefix>(pointer);
                        var callout = (item.Action.Type & 0x4000) != 0;
                        if (callout) calloutCount++;
                        var target = callout ? callouts : filters;
                        if (target.Count < maxShown)
                        {
                            Guid? provider = item.Provider == IntPtr.Zero ? null : Marshal.PtrToStructure<Guid>(item.Provider);
                            target.Add(new WfpFilterRecord(item.Key, item.Layer, provider,
                                ActionName(item.Action.Type), (item.Flags & 0x20) != 0, callout ? item.Action.Key : null));
                        }
                        scanned++;
                        if (scanned > maxShown) truncated = true;
                    }
                    if (count < request) break;
                    if (scanned >= maxScanned) truncated = true;
                }
                finally { if (entries != IntPtr.Zero) Native.FreeMemory(ref entries); }
            }
            return new WfpSnapshot([.. callouts.Concat(filters).Take(maxShown)], scanned, calloutCount, truncated, null);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) { return new WfpSnapshot([.. callouts.Concat(filters).Take(maxShown)], scanned, calloutCount, true, ex.GetBaseException().Message); }
        finally { if (enumerator != IntPtr.Zero) _ = Native.DestroyEnum(engine, enumerator); }
    }

    private static string ActionName(uint action) => action switch
    {
        0x1001 => "BLOCK",
        0x1002 => "PERMIT",
        0x5003 => "CALLOUT_TERMINATING",
        0x6004 => "CALLOUT_INSPECTION",
        0x4005 => "CALLOUT_UNKNOWN",
        0x2006 => "CONTINUE",
        _ => "0x" + action.ToString("X8", CultureInfo.InvariantCulture),
    };

    private static async Task<ObservationPart> ObserveEtwAsync(TimeSpan duration, CancellationToken ct)
    {
        var buffer = new ObservationBuffer(250);
        try
        {
            // Уникальная real-time сессия: не переиспользуем и не останавливаем чужие сессии.
            using var session = new TraceEventSession("NetworkChecker-TcpIp-" + Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture));
            session.Source.Dynamic.All += e => buffer.Add(new ObservationEvent("ETW", e.EventName ?? "event", $"PID {e.ProcessID.ToString(CultureInfo.InvariantCulture)}", DateTimeOffset.Now));
            var provider = TraceEventProviders.GetProviderGuidByName("Microsoft-Windows-TCPIP");
            if (provider == Guid.Empty) throw new InvalidOperationException("ETW-поставщик Microsoft-Windows-TCPIP не зарегистрирован.");
            session.EnableProvider(provider, TraceEventLevel.Verbose);
            var reader = Task.Run(() => session.Source.Process(), CancellationToken.None);
            int? lost = null;
            try
            {
                var wait = Task.Delay(duration, ct);
                if (await Task.WhenAny(wait, reader).ConfigureAwait(false) == reader)
                {
                    await reader.ConfigureAwait(false);
                    throw new InvalidOperationException("Поток ETW завершился раньше времени.");
                }
                await wait.ConfigureAwait(false);
            }
            finally
            {
                try { lost = session.EventsLost; } catch { /* Счётчик потерь может быть недоступен. */ }
                session.Stop();
                await reader.WaitAsync(TimeSpan.FromSeconds(5), CancellationToken.None).ConfigureAwait(false);
            }
            var result = buffer.Snapshot();
            return new ObservationPart("ETW", true, $"Показаны события Microsoft-Windows-TCPIP; наличие события не подтверждает перехват. Потеряно ETW: {(lost?.ToString(CultureInfo.InvariantCulture) ?? "неизвестно")}", result.Events, result.Dropped);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            var result = buffer.Snapshot();
            return new ObservationPart("ETW", true, "Наблюдение остановлено пользователем.", result.Events, result.Dropped);
        }
        catch (Exception ex)
        {
            var result = buffer.Snapshot();
            return new ObservationPart("ETW", false, ex.GetBaseException().Message, result.Events, result.Dropped);
        }
    }

    private static void Check(uint code, string api)
    {
        if (code != 0) throw new InvalidOperationException($"{api}: 0x{code:X8} ({new Win32Exception(unchecked((int)code)).Message})");
    }

    private static class Native
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct FilterSubscription { public IntPtr Template; public uint Flags; public Guid SessionKey; }
        [StructLayout(LayoutKind.Sequential)]
        internal struct FilterChange { public uint Type; public Guid Key; public ulong Id; }
        [StructLayout(LayoutKind.Sequential)]
        internal struct DisplayData { public IntPtr Name; public IntPtr Description; }
        [StructLayout(LayoutKind.Sequential)]
        internal struct Blob { public uint Size; public IntPtr Data; }
        [StructLayout(LayoutKind.Sequential)]
        internal struct Value { public uint Type; public IntPtr ValuePointer; }
        [StructLayout(LayoutKind.Sequential)]
        internal struct Action { public uint Type; public Guid Key; }
        // Префикс FWPM_FILTER0 до action включительно; остальную часть не читаем.
        [StructLayout(LayoutKind.Sequential)]
        internal struct FilterPrefix
        {
            public Guid Key; public DisplayData Display; public uint Flags; public IntPtr Provider;
            public Blob ProviderData; public Guid Layer; public Guid SubLayer; public Value Weight;
            public uint ConditionCount; public IntPtr Conditions; public Action Action;
        }
        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        internal delegate void FilterCallback(IntPtr context, IntPtr change);

#pragma warning disable SYSLIB1054
        [DllImport("fwpuclnt.dll", EntryPoint = "FwpmEngineOpen0", CharSet = CharSet.Unicode)]
        internal static extern uint EngineOpen(string? server, uint auth, IntPtr identity, IntPtr session, out IntPtr engine);
        [DllImport("fwpuclnt.dll", EntryPoint = "FwpmEngineClose0")]
        internal static extern uint EngineClose(IntPtr engine);
        [DllImport("fwpuclnt.dll", EntryPoint = "FwpmFilterCreateEnumHandle0")]
        internal static extern uint CreateEnum(IntPtr engine, IntPtr template, out IntPtr handle);
        [DllImport("fwpuclnt.dll", EntryPoint = "FwpmFilterEnum0")]
        internal static extern uint EnumFilters(IntPtr engine, IntPtr handle, uint requested, out IntPtr entries, out uint returned);
        [DllImport("fwpuclnt.dll", EntryPoint = "FwpmFilterDestroyEnumHandle0")]
        internal static extern uint DestroyEnum(IntPtr engine, IntPtr handle);
        [DllImport("fwpuclnt.dll", EntryPoint = "FwpmFreeMemory0")]
        internal static extern void FreeMemory(ref IntPtr memory);
        [DllImport("fwpuclnt.dll", EntryPoint = "FwpmFilterSubscribeChanges0")]
        internal static extern uint Subscribe(IntPtr engine, ref FilterSubscription subscription, FilterCallback callback, IntPtr context, out IntPtr handle);
        [DllImport("fwpuclnt.dll", EntryPoint = "FwpmFilterUnsubscribeChanges0")]
        internal static extern uint Unsubscribe(IntPtr engine, IntPtr handle);
#pragma warning restore SYSLIB1054
    }
}
