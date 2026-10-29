using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace RKNHardering.App.ViewModels;

public sealed partial class MainWindowViewModel : ViewModelBase
{
    public MainWindowViewModel(
        DashboardViewModel dashboard,
        NetworkViewModel network,
        HistoryViewModel history,
        GuideViewModel guide,
        SettingsViewModel settings)
    {
        Pages = new ObservableCollection<ViewModelBase> { dashboard, network, history, guide, settings };
        NavItems = new ObservableCollection<NavItem>(Pages.Select(p => new NavItem(p) { Command = NavigateCommand }));
        NavItems[0].IsSelected = true;
        _currentNav = NavItems[0];
        _currentPage = dashboard;
    }

    public override string Title => "RKNHardering PC";
    public override string Icon => "\uE7F4";

    public ObservableCollection<ViewModelBase> Pages { get; }
    public ObservableCollection<NavItem> NavItems { get; }

    [ObservableProperty] private ViewModelBase _currentPage;
    [ObservableProperty] private NavItem _currentNav;
    [ObservableProperty] private bool _isNavExpanded = true;

    [RelayCommand]
    private void Navigate(NavItem? item)
    {
        if (item is null) return;
        CurrentNav = item;
        CurrentPage = item.Page;
        foreach (var nav in NavItems) nav.IsSelected = ReferenceEquals(nav, item);
    }

    [RelayCommand]
    private void ToggleNav() => IsNavExpanded = !IsNavExpanded;
}
