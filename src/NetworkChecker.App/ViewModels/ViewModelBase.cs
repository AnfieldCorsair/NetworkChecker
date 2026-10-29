using Avalonia.Media;
using CommunityToolkit.Mvvm.ComponentModel;

namespace NetworkChecker.App.ViewModels;

public abstract class ViewModelBase : ObservableObject
{
    public abstract string Title { get; }
    /// <summary>Path data иконки.</summary>
    public virtual string Icon => global::NetworkChecker.App.Icons.Shield;
    public virtual string Description => string.Empty;
}

/// <summary>Элемент боковой навигации.</summary>
public sealed partial class NavItem(ViewModelBase page) : ObservableObject
{
    public ViewModelBase Page { get; } = page;
    public string Title => Page.Title;
    public string Description => Page.Description;
    public string Icon => Page.Icon;
    public Geometry IconGeometry => Geometry.Parse(Page.Icon);

    public CommunityToolkit.Mvvm.Input.IRelayCommand? Command { get; init; }

    [ObservableProperty]
    public partial bool IsSelected { get; set; }
}
