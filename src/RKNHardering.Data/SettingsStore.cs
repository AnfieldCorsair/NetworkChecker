using System.Text.Json;
using RKNHardering.Core.Options;

namespace RKNHardering.Data;

/// <summary>Настройки приложения в %LOCALAPPDATA%\RKNHarderingPC\settings.json.</summary>
public sealed class SettingsStore
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web) { WriteIndented = true };
    private readonly string _path;

    public SettingsStore(string? directory = null)
    {
        var root = directory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "RKNHarderingPC");
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

    public void Save()
    {
        try
        {
            var envelope = new SettingsEnvelope { Options = Options, Ui = Ui };
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
