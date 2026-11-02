namespace NetworkChecker.Core.Models;

/// <summary>Состояние одного сигнала в матрице соответствия методике.</summary>
public enum MethodologySignalState
{
    /// <summary>Данных нет: модуль не запускался, пропущен или источник не ответил.</summary>
    Unknown = 0,
    /// <summary>Проверка выполнена, сигнал не найден.</summary>
    Absent = 1,
    /// <summary>Сигнал найден; это наблюдение, а не доказательство.</summary>
    Present = 2,
}

/// <summary>Одна строка матрицы «метод обнаружения → что видно в этом прогоне».</summary>
public sealed record MethodologySignal(string Stage, string Name, MethodologySignalState State, string Note);

/// <summary>
/// Модель соответствия прогона опубликованной трёхэтапной методике. Это не решение
/// конкретного сайта, ведомства или приложения и не вероятность использования VPN.
/// </summary>
public sealed record MethodologyAssessment(
    IReadOnlyList<MethodologySignal> Signals,
    string Decision,
    string Explanation,
    bool HasServerSideSignal,
    bool HasDeviceSideSignal,
    bool HasMissingData,
    bool RouterVpnHint,
    IReadOnlyList<string> FalsePositiveCaveats,
    IReadOnlyList<string> NotMeasurable);
