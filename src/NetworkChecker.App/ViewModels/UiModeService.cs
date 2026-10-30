using CommunityToolkit.Mvvm.ComponentModel;
using NetworkChecker.Core.Options;

namespace NetworkChecker.App.ViewModels;

/// <summary>
/// Режим интерфейса. Проект двойного назначения: «Просто» — понятные ответы для обычных
/// пользователей, «Подробно» — метрики, находки и сырые данные для тех, кому нужны детали.
/// </summary>
public sealed partial class UiModeService(UiOptions ui, Data.SettingsStore? store = null) : ObservableObject
{
    private readonly UiOptions _ui = ui;
    private readonly Data.SettingsStore? _store = store;
    [ObservableProperty]
    public partial bool IsSimple { get; set; } = !ui.ProModeByDefault;
    public bool IsPro
    {
        get => !IsSimple;
        set => IsSimple = !value;
    }

    partial void OnIsSimpleChanged(bool value)
    {
        _ui.ProModeByDefault = !value;
        _store?.Save(_store.Options, _ui);
        OnPropertyChanged(nameof(IsPro));
        OnPropertyChanged(nameof(ModeText));
    }

    public string ModeText => Localization.Localizer.T(IsSimple ? "Просто" : "Подробно");
}
