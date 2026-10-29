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
        var wfp = ObserveWfpAsync(duration, cancellationToken);
        var etw = ObserveEtwAsync(duration, cancellationToken);
        return new ObservationReport(await wfp.ConfigureAwait(false), await etw.ConfigureAwait(false));
    }

    private static async Task<ObservationPart> ObserveWfpAsync(TimeSpan duration, CancellationToken ct)
    {
        var buffer = new ObservationBuffer(250);
        IntPtr engine = IntPtr.Zero, subscription = IntPtr.Zero;
        Native.FilterCallback? callback = null;
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
            Check(Native.Subscribe(engine, ref options, callback, IntPtr.Zero, out subscription), "FwpmFilterSubscribeChanges0");
            await Task.Delay(duration, ct).ConfigureAwait(false);
            var result = buffer.Snapshot();
            return new ObservationPart("WFP", true, "Подписка выполнена; показаны изменения во время наблюдения, не полный список фильтров.", result.Events, result.Dropped);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            var result = buffer.Snapshot();
            return new ObservationPart("WFP", true, "Наблюдение остановлено пользователем.", result.Events, result.Dropped);
        }
        catch (Exception ex)
        {
            var result = buffer.Snapshot();
            return new ObservationPart("WFP", false, ex.GetBaseException().Message, result.Events, result.Dropped);
        }
        finally
        {
            if (subscription != IntPtr.Zero) _ = Native.Unsubscribe(engine, subscription);
            if (engine != IntPtr.Zero) _ = Native.EngineClose(engine);
            GC.KeepAlive(callback);
        }
    }

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
        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        internal delegate void FilterCallback(IntPtr context, IntPtr change);

#pragma warning disable SYSLIB1054
        [DllImport("fwpuclnt.dll", EntryPoint = "FwpmEngineOpen0", CharSet = CharSet.Unicode)]
        internal static extern uint EngineOpen(string? server, uint auth, IntPtr identity, IntPtr session, out IntPtr engine);
        [DllImport("fwpuclnt.dll", EntryPoint = "FwpmEngineClose0")]
        internal static extern uint EngineClose(IntPtr engine);
        [DllImport("fwpuclnt.dll", EntryPoint = "FwpmFilterSubscribeChanges0")]
        internal static extern uint Subscribe(IntPtr engine, ref FilterSubscription subscription, FilterCallback callback, IntPtr context, out IntPtr handle);
        [DllImport("fwpuclnt.dll", EntryPoint = "FwpmFilterUnsubscribeChanges0")]
        internal static extern uint Unsubscribe(IntPtr engine, IntPtr handle);
#pragma warning restore SYSLIB1054
    }
}
