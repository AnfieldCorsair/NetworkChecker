using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace NetworkChecker.App.ViewModels;

public abstract partial class ViewModelBase : ObservableObject
{
    public abstract string Title { get; }
    public virtual string Subtitle => string.Empty;
    public virtual string Description => string.Empty;

    /// <summary>
    /// Понятная подсказка «для обычного пользователя»: что делает этот экран и какую кнопку нажать.
    /// </summary>
    public virtual string SimpleGuideText => Description;

    /// <summary>
    /// Управляет отображением инженерных подробностей (сырые параметры протокола, JSON, трассировка).
    /// В Простом режиме (false) карточки показывают только человеческое объяснение, а техдетали спрятаны под спойлер.
    /// </summary>
    [ObservableProperty]
    public partial bool ShowTechnicalDetails { get; set; }
}

public sealed partial class NavItem : ObservableObject
{
    public NavItem(int stepNumber, ViewModelBase page, Action<ViewModelBase> onSelect)
    {
        StepNumber = stepNumber;
        Page = page;
        SelectCommand = new RelayCommand(() => onSelect(page));
    }

    public int StepNumber { get; }
    public ViewModelBase Page { get; }
    public string StepBadge => $"ШАГ {StepNumber}";
    public string Title => Page.Title;
    public string Subtitle => Page.Subtitle;
    public IRelayCommand SelectCommand { get; }

    [ObservableProperty]
    public partial bool IsSelected { get; set; }
}
