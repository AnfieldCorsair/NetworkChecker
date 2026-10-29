using Xunit;

// Тесты UI работают с общими статическими состояними Avalonia (текущее приложение, тема,
// Masking.Enabled). Параллельный запуск даёт плавающие падения, поэтому — последовательно.
[assembly: CollectionBehavior(DisableTestParallelization = true)]
