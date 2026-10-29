using CommunityToolkit.Mvvm.ComponentModel;
using RKNHardering.Core.Options;

namespace RKNHardering.App.ViewModels;

/// <summary>
/// Режим интерфейса. Проект двойного назначения: «Просто» — понятные ответы для обычных
/// пользователей, «Подробно» — метрики, находки и сырые данные для тех, кому нужны детали.
/// </summary>
public sealed partial class UiModeService : ObservableObject
{
    private readonly UiOptions _ui;
    private readonly Data.SettingsStore? _store;

    public UiModeService(UiOptions ui, Data.SettingsStore? store = null)
    {
        _ui = ui;
        _store = store;
        _isSimple = !ui.ProModeByDefault;
    }

    [ObservableProperty]
    private bool _isSimple;

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

    public string ModeText => IsSimple ? "Просто" : "Подробно";
}
