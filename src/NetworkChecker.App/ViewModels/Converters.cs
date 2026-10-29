using Avalonia.Data.Converters;
using Avalonia.Media;

namespace NetworkChecker.App.ViewModels;

/// <summary>Мелкие конвертеры, которых нет в Avalonia из коробки.</summary>
public static class Converters
{
    /// <summary>Маршрут по умолчанию подсвечивается акцентным цветом.</summary>
    public static readonly IValueConverter DefaultRouteBrush = new FuncValueConverter<bool, IBrush>(
        isDefault => Ui.Brush(isDefault ? "#4EA1FF" : "#C9D6E4"));
}
