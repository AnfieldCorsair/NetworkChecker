using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace NetworkChecker.App.ViewModels;

public sealed partial class MainWindowViewModel : ViewModelBase, IDisposable
{
    public MainWindowViewModel(
        DashboardViewModel dashboard,
        NetworkViewModel network,
        SiteViewModel site,
        HistoryViewModel history,
        GuideViewModel guide,
        SettingsViewModel settings,
        UiModeService mode,
        ObservationViewModel observation,
        CaptureViewModel capture)
    {
        Mode = mode;
        Pages = [dashboard, network, site, history, guide, settings, observation, capture];
        NavItems = new ObservableCollection<NavItem>(Pages.Select(p => new NavItem(p) { Command = NavigateCommand }));
        NavItems[0].IsSelected = true;
        CurrentNav = NavItems[0];
        CurrentPage = dashboard;
    }

    public UiModeService Mode { get; }

    public override string Title => "NetworkChecker";
    public override string Icon => "\uE7F4";

    public ObservableCollection<ViewModelBase> Pages { get; }
    public ObservableCollection<NavItem> NavItems { get; }

    [ObservableProperty]
    public partial ViewModelBase CurrentPage { get; set; }

    [ObservableProperty]
    public partial NavItem CurrentNav { get; set; }

    [ObservableProperty]
    public partial bool IsNavExpanded { get; set; } = true;

    [RelayCommand]
    private void Navigate(NavItem? item)
    {
        if (item is null) return;
        CurrentNav = item;
        CurrentPage = item.Page;
        foreach (var nav in NavItems) nav.IsSelected = ReferenceEquals(nav, item);
        // Экран «Глазами сайта» подгружает данные сам — вкладку открывают, чтобы сразу увидеть ответ.
        if (item.Page is SiteViewModel site) site.EnsureLoaded();
    }

    [RelayCommand]
    private void ToggleNav() => IsNavExpanded = !IsNavExpanded;

    [RelayCommand]
    private void SetProMode(bool pro) => Mode.IsSimple = !pro;

    /// <summary>Переключатель в шапке: "simple" или "pro".</summary>
    [RelayCommand]
    private void SwitchMode(string? value) => Mode.IsSimple = value != "pro";

    public bool IsSimpleMode => Mode.IsSimple;
    public bool IsProMode => Mode.IsPro;

    /// <summary>Останавливает незавершённые операции на всех экранах.</summary>
    public void Dispose()
    {
        foreach (var page in Pages)
        {
            if (page is IDisposable disposable) disposable.Dispose();
        }
    }
}
