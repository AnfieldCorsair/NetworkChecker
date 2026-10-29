using Avalonia.Media;
using CommunityToolkit.Mvvm.ComponentModel;

namespace RKNHardering.App.ViewModels;

public abstract class ViewModelBase : ObservableObject
{
    public abstract string Title { get; }
    /// <summary>Path data иконки.</summary>
    public virtual string Icon => global::RKNHardering.App.Icons.Shield;
    public virtual string Description => string.Empty;
}

/// <summary>Элемент боковой навигации.</summary>
public sealed partial class NavItem : ObservableObject
{
    public NavItem(ViewModelBase page)
    {
        Page = page;
    }

    public ViewModelBase Page { get; }
    public string Title => Page.Title;
    public string Description => Page.Description;
    public string Icon => Page.Icon;
    public Geometry IconGeometry => Geometry.Parse(Page.Icon);

    public CommunityToolkit.Mvvm.Input.IRelayCommand? Command { get; init; }

    [ObservableProperty]
    private bool _isSelected;
}
