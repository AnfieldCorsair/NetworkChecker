using Avalonia.Headless.XUnit;
using NetworkChecker.App.ViewModels;
using NetworkChecker.Core.Observation;
using NetworkChecker.Platform.Windows;
using Xunit;

namespace NetworkChecker.App.Tests;

public class ObservationTests
{
    [AvaloniaFact]
    public async Task Explicit_consent_required_and_reset_after_run()
    {
        var fake = new FakeObservationService();
        var vm = new ObservationViewModel(fake);
        Assert.False(vm.StartCommand.CanExecute(null));
        vm.Consented = true;
        Assert.True(vm.StartCommand.CanExecute(null));
        await vm.StartCommand.ExecuteAsync(null);
        Assert.False(vm.Consented);
        Assert.False(vm.IsRunning);
        Assert.Contains("test", vm.WfpStatus);
        Assert.Contains("test", vm.EtwStatus);
    }

    [Fact]
    public async Task Non_windows_is_reported_as_unavailable()
    {
        if (OperatingSystem.IsWindows()) return;
        var report = await new WindowsObservationService().ObserveAsync(TimeSpan.FromSeconds(1), CancellationToken.None);
        Assert.False(report.Wfp.Available);
        Assert.False(report.Etw.Available);
        Assert.Empty(report.Wfp.Events);
        Assert.Empty(report.Etw.Events);
    }

    [AvaloniaFact]
    public async Task Each_source_has_its_own_failure_status()
    {
        var vm = new ObservationViewModel(new PartialFake());
        vm.Consented = true;
        await vm.StartCommand.ExecuteAsync(null);
        Assert.Contains("нет доступа", vm.WfpStatus);
        Assert.Contains("работает", vm.EtwStatus);
        Assert.Single(vm.Events);
    }

    [AvaloniaFact]
    public async Task Stop_cancels_running_service_and_resets_consent()
    {
        var fake = new WaitingFake();
        var vm = new ObservationViewModel(fake) { Consented = true };
        var run = vm.StartCommand.ExecuteAsync(null);
        await fake.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.True(vm.IsRunning);
        vm.StopCommand.Execute(null);
        await run.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.True(fake.Cancelled);
        Assert.False(vm.IsRunning);
        Assert.False(vm.Consented);
    }

    private sealed class WaitingFake : IObservationService
    {
        public TaskCompletionSource<bool> Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public bool Cancelled { get; private set; }
        public async Task<ObservationReport> ObserveAsync(TimeSpan duration, CancellationToken cancellationToken)
        {
            Started.TrySetResult(true);
            try { await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken); }
            catch (OperationCanceledException) { Cancelled = true; }
            var part = new ObservationPart("test", true, "stopped", [], 0);
            return new ObservationReport(part, part);
        }
    }

    private sealed class PartialFake : IObservationService
    {
        public Task<ObservationReport> ObserveAsync(TimeSpan duration, CancellationToken cancellationToken) => Task.FromResult(
            new ObservationReport(new("WFP", false, "нет доступа", [], 0),
                new("ETW", true, "работает", [new ObservationEvent("ETW", "event", "PID 1", DateTimeOffset.UtcNow)], 0)));
    }
}
