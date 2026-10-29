using System.Text.Json;
using NetworkChecker.Core.Options;

namespace NetworkChecker.Data;

/// <summary>Настройки приложения в %LOCALAPPDATA%\NetworkChecker\settings.json.</summary>
public sealed class SettingsStore
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web) { WriteIndented = true };
    private readonly string _path;

    public SettingsStore(string? directory = null)
    {
        var root = directory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "NetworkChecker");
        Directory.CreateDirectory(root);
        _path = Path.Combine(root, "settings.json");
        DataDirectory = root;
    }

    public string DataDirectory { get; }
    public string DatabasePath => Path.Combine(DataDirectory, "history.db");
    public string LogPath => Path.Combine(DataDirectory, "logs", "app-.log");

    public RknOptions Options { get; private set; } = new();
    public UiOptions Ui { get; private set; } = new();

    public RknOptions Load()
    {
        try
        {
            if (File.Exists(_path))
            {
                var envelope = JsonSerializer.Deserialize<SettingsEnvelope>(File.ReadAllText(_path), JsonOptions);
                if (envelope is not null)
                {
                    Options = envelope.Options ?? new RknOptions();
                    Ui = envelope.Ui ?? new UiOptions();
                }
            }
        }
        catch
        {
            Options = new RknOptions();
            Ui = new UiOptions();
        }
        return Options;
    }

    public void Save() => Save(Options, Ui);

    /// <summary>
    /// Сохраняет явно переданные экземпляры. Страховка от рассинхронизации: если настройки
    /// в UI живут в другом объекте, чем <see cref="Options"/>, они всё равно попадут в файл,
    /// а не будут молча затёрты дефолтами.
    /// </summary>
    public void Save(RknOptions options, UiOptions ui)
    {
        Options = options;
        Ui = ui;
        try
        {
            var envelope = new SettingsEnvelope { Options = options, Ui = ui };
            File.WriteAllText(_path, JsonSerializer.Serialize(envelope, JsonOptions));
        }
        catch
        {
            // настройки не критичны: молча живём с дефолтами
        }
    }

    private sealed class SettingsEnvelope
    {
        public RknOptions? Options { get; set; }
        public UiOptions? Ui { get; set; }
    }
}
