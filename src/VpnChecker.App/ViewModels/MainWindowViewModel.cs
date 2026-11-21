using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace VpnChecker.App.ViewModels;

public sealed partial class MainWindowViewModel : ObservableObject
{
    private readonly ConfigAuditViewModel _configAudit;
    private readonly NavItem[] _allNavItems;

    public MainWindowViewModel(
        ConfigAuditViewModel configAudit,
        DnsArchitectViewModel dnsArchitect,
        TspuFingerprintsViewModel tspuFingerprints,
        WindowsStackSniViewModel windowsStackSni,
        IpReputationViewModel ipReputation,
        SupportTicketViewModel supportTicket)
    {
        _configAudit = configAudit;
        _allNavItems =
        [
            new NavItem(1, configAudit, isBasicTab: true, SelectPage),
            new NavItem(2, dnsArchitect, isBasicTab: false, SelectPage),
            new NavItem(3, tspuFingerprints, isBasicTab: false, SelectPage),
            new NavItem(4, windowsStackSni, isBasicTab: false, SelectPage),
            new NavItem(5, ipReputation, isBasicTab: true, SelectPage),
            new NavItem(6, supportTicket, isBasicTab: true, SelectPage),
        ];

        VisibleNavItems = [];
        RebuildVisibleNavItems();

        CurrentPage = configAudit;
        SelectPage(configAudit);
    }

    public ObservableCollection<NavItem> VisibleNavItems { get; }

    [ObservableProperty]
    public partial ViewModelBase CurrentPage { get; set; }

    [ObservableProperty]
    public partial bool IsAdvancedMode { get; set; }

    public string ModeButtonLabel => IsAdvancedMode
        ? "Расширенный режим (6 вкладок)"
        : "Базовый режим (3 вкладки)";

    public string ModeHintText => IsAdvancedMode
        ? "Открыты все инженерные инструменты и 6 вкладок"
        : "Минималистичный режим · нажмите для всех 6 вкладок";

    partial void OnIsAdvancedModeChanged(bool value)
    {
        OnPropertyChanged(nameof(ModeButtonLabel));
        OnPropertyChanged(nameof(ModeHintText));

        foreach (var item in _allNavItems)
        {
            item.Page.ShowTechnicalDetails = value;
        }

        RebuildVisibleNavItems();

        if (!value)
        {
            var currentItem = _allNavItems.FirstOrDefault(i => ReferenceEquals(i.Page, CurrentPage));
            if (currentItem is not null && !currentItem.IsBasicTab)
            {
                SelectPage(_configAudit);
            }
        }
    }

    [RelayCommand]
    private void ToggleMode()
    {
        IsAdvancedMode = !IsAdvancedMode;
    }

    private void RebuildVisibleNavItems()
    {
        VisibleNavItems.Clear();
        var step = 1;
        foreach (var item in _allNavItems)
        {
            if (IsAdvancedMode || item.IsBasicTab)
            {
                item.StepNumber = step++;
                VisibleNavItems.Add(item);
            }
        }
    }

    private void SelectPage(ViewModelBase page)
    {
        page.ShowTechnicalDetails = IsAdvancedMode;
        CurrentPage = page;
        foreach (var item in _allNavItems)
        {
            item.IsSelected = ReferenceEquals(item.Page, page);
        }
    }
}
