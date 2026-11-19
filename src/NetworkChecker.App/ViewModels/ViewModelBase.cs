using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace NetworkChecker.App.ViewModels;

public abstract class ViewModelBase : ObservableObject
{
    public abstract string Title { get; }
    public virtual string Subtitle => string.Empty;
    public virtual string Description => string.Empty;
}

public sealed partial class NavItem : ObservableObject
{
    public NavItem(ViewModelBase page, Action<ViewModelBase> onSelect)
    {
        Page = page;
        SelectCommand = new RelayCommand(() => onSelect(page));
    }

    public ViewModelBase Page { get; }
    public string Title => Page.Title;
    public string Subtitle => Page.Subtitle;
    public IRelayCommand SelectCommand { get; }

    [ObservableProperty]
    public partial bool IsSelected { get; set; }
}
