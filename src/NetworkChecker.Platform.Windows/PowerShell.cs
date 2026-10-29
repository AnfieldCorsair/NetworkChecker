using System.Diagnostics;
using System.Text;
using System.Text.Json;

namespace NetworkChecker.Platform.Windows;

/// <summary>
/// Тонкая обёртка над powershell.exe. Возвращает JSON и никогда не бросает:
/// на не-Windows среде просто отдаёт пустой результат.
/// </summary>
public static class PowerShell
{
    public static bool IsAvailable => OperatingSystem.IsWindows();

    public static async Task<JsonElement?> QueryJsonAsync(string script, TimeSpan timeout, CancellationToken ct = default)
    {
        if (!IsAvailable) return null;
        var command = "$ProgressPreference='SilentlyContinue';" + script + " | ConvertTo-Json -Depth 4 -Compress";
        var output = await RunAsync(command, timeout, ct).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(output)) return null;
        try
        {
            using var doc = JsonDocument.Parse(output);
            return doc.RootElement.Clone();
        }
        catch
        {
            return null;
        }
    }

    public static async Task<string> RunAsync(string command, TimeSpan timeout, CancellationToken ct = default)
    {
        if (!IsAvailable) return string.Empty;
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"{command.Replace("\"", "\\\"")}\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8,
            };
            using var process = Process.Start(psi);
            if (process is null) return string.Empty;
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeout);
            var stdout = await process.StandardOutput.ReadToEndAsync(cts.Token).ConfigureAwait(false);
            await process.WaitForExitAsync(cts.Token).ConfigureAwait(false);
            return stdout.Trim();
        }
        catch
        {
            return string.Empty;
        }
    }

    public static IEnumerable<JsonElement> Enumerate(JsonElement? root)
    {
        if (root is null) yield break;
        var element = root.Value;
        if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray()) yield return item;
        }
        else if (element.ValueKind == JsonValueKind.Object)
        {
            yield return element;
        }
    }

    public static string? Text(this JsonElement element, string property)
    {
        if (element.ValueKind != JsonValueKind.Object) return null;
        foreach (var prop in element.EnumerateObject())
        {
            if (!prop.Name.Equals(property, StringComparison.OrdinalIgnoreCase)) continue;
            return prop.Value.ValueKind switch
            {
                JsonValueKind.String => prop.Value.GetString(),
                JsonValueKind.Number => prop.Value.ToString(),
                JsonValueKind.True => "true",
                JsonValueKind.False => "false",
                JsonValueKind.Array => string.Join(", ", prop.Value.EnumerateArray()
                    .Select(v => v.ValueKind == JsonValueKind.String ? v.GetString() : v.ToString())),
                _ => null,
            };
        }
        return null;
    }

    public static int Number(this JsonElement element, string property, int fallback = 0) =>
        int.TryParse(element.Text(property), out var value) ? value : fallback;
}
