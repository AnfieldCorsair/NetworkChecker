using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace NetworkChecker.App.ViewModels;

public sealed partial class MainWindowViewModel : ObservableObject
{
    private readonly ViewModelBase[] _pages;

    public MainWindowViewModel(
        ConfigAuditViewModel configAudit,
        DnsArchitectViewModel dnsArchitect,
        TspuFingerprintsViewModel tspuFingerprints,
        WindowsStackSniViewModel windowsStackSni,
        SupportTicketViewModel supportTicket)
    {
        _pages =
        [
            configAudit,
            dnsArchitect,
            tspuFingerprints,
            windowsStackSni,
            supportTicket,
        ];

        NavItems = new ObservableCollection<NavItem>(
            _pages.Select((p, idx) => new NavItem(idx + 1, p, SelectPage)));

        CurrentPage = configAudit;
        SelectPage(configAudit);
    }

    public ObservableCollection<NavItem> NavItems { get; }

    [ObservableProperty]
    public partial ViewModelBase CurrentPage { get; set; }

    [ObservableProperty]
    public partial bool IsEngineeringMode { get; set; }

    public string ModeButtonLabel => IsEngineeringMode
        ? "Режим: Инженерный (все техдетали открыты)"
        : "Режим: Простой (понятно каждому)";

    partial void OnIsEngineeringModeChanged(bool value)
    {
        OnPropertyChanged(nameof(ModeButtonLabel));
        foreach (var page in _pages)
        {
            page.ShowTechnicalDetails = value;
        }
    }

    [RelayCommand]
    private void ToggleMode()
    {
        IsEngineeringMode = !IsEngineeringMode;
    }

    private void SelectPage(ViewModelBase page)
    {
        page.ShowTechnicalDetails = IsEngineeringMode;
        CurrentPage = page;
        foreach (var item in NavItems)
        {
            item.IsSelected = ReferenceEquals(item.Page, page);
        }
    }
}
