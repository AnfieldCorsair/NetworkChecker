using Avalonia.Controls;
using Avalonia.Controls.Templates;
using VpnChecker.App.ViewModels;
using VpnChecker.App.Views;

namespace VpnChecker.App;

/// <summary>
/// Детерминированный ViewLocator без reflection — полностью совместим с PublishSingleFile и AOT.
/// </summary>
public sealed class ViewLocator : IDataTemplate
{
    public Control? Build(object? param) => param switch
    {
        ConfigAuditViewModel => new ConfigAuditView(),
        DnsArchitectViewModel => new DnsArchitectView(),
        TspuFingerprintsViewModel => new TspuFingerprintsView(),
        WindowsStackSniViewModel => new WindowsStackSniView(),
        IpReputationViewModel => new IpReputationView(),
        SupportTicketViewModel => new SupportTicketView(),
        _ => param is null ? null : new TextBlock { Text = $"Экран не найден: {param.GetType().Name}" },
    };

    public bool Match(object? data) => data is ViewModelBase;
}
