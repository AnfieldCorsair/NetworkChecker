using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;

namespace NetworkChecker.App.ViewModels;

public sealed partial class MainWindowViewModel : ObservableObject
{
    public MainWindowViewModel(
        ConfigAuditViewModel configAudit,
        DnsArchitectViewModel dnsArchitect,
        TspuFingerprintsViewModel tspuFingerprints,
        WindowsStackSniViewModel windowsStackSni,
        SupportTicketViewModel supportTicket)
    {
        ViewModelBase[] pages =
        [
            configAudit,
            dnsArchitect,
            tspuFingerprints,
            windowsStackSni,
            supportTicket,
        ];

        NavItems = new ObservableCollection<NavItem>(
            pages.Select(p => new NavItem(p, SelectPage)));

        CurrentPage = configAudit;
        SelectPage(configAudit);
    }

    public ObservableCollection<NavItem> NavItems { get; }

    [ObservableProperty]
    public partial ViewModelBase CurrentPage { get; set; }

    private void SelectPage(ViewModelBase page)
    {
        CurrentPage = page;
        foreach (var item in NavItems)
        {
            item.IsSelected = ReferenceEquals(item.Page, page);
        }
    }
}
