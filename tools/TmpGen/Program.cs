using RKNHardering.Export;
using RKNHardering.TestKit;
var run = Sample.RichRun();
foreach (var (format, title, ext, _) in ReportExporter.Catalog)
{
    var file = ReportExporter.Build(format, run, "sample-report");
    File.WriteAllBytes("/tmp/pdfcheck/" + file.FileName, file.Content);
    Console.WriteLine($"{title}: {file.Content.Length} байт");
}
