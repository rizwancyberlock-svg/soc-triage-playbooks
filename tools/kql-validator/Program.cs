// KQL validator for sentinel-kql-detections.
//
// Parses every rule's `query` with Microsoft's Sentinel KQL analyzer and checks it
// semantically against the real Microsoft Sentinel table schemas (built-in tables
// plus the custom-table JSON schemas published in Azure/Azure-Sentinel).
//
// Usage: dotnet run -- <rules-dir> <azure-sentinel-KqlvalidationsTests-dir>
// Exit code 1 when any query has errors.

using Microsoft.Azure.Sentinel.KustoServices.Contract;
using Microsoft.Azure.Sentinel.KustoServices.Implementation;
using YamlDotNet.Serialization;

if (args.Length < 2)
{
    Console.Error.WriteLine("usage: KqlValidator <rules-dir> <KqlvalidationsTests-dir>");
    return 2;
}

var rulesDir = args[0];
var schemaRoot = args[1];
var customTables = Path.Combine(schemaRoot, "CustomTables");
var customFunctions = Path.Combine(schemaRoot, "CustomFunctions");

var analyzer = new KqlQueryAnalyzerBuilder()
    .WithCustomTableSchemasLoader(new LocalOverrideTablesLoader(customTables))
    .WithCustomFunctionSchemasLoader(new SentinelDefaultFunctionsLoader())
    .WithCustomFunctionSchemasLoader(new CustomJsonDirectoryFunctionsLoader(customFunctions))
    .Build();

var deserializer = new DeserializerBuilder().Build();
var files = Directory.GetFiles(rulesDir, "*.yaml", SearchOption.AllDirectories).OrderBy(f => f).ToList();
var failed = 0;

foreach (var file in files)
{
    var rel = Path.GetRelativePath(rulesDir, file).Replace('\\', '/');
    Dictionary<string, object> doc;
    try
    {
        doc = deserializer.Deserialize<Dictionary<string, object>>(File.ReadAllText(file));
    }
    catch (Exception ex)
    {
        Console.WriteLine($"FAIL  {rel}: YAML parse error: {ex.Message}");
        failed++;
        continue;
    }

    if (!doc.TryGetValue("query", out var q) || q is not string query || string.IsNullOrWhiteSpace(query))
    {
        Console.WriteLine($"FAIL  {rel}: missing query");
        failed++;
        continue;
    }

    var result = analyzer.ValidateSyntax(query);
    var diagnostics = (result.Diagnostics ?? Enumerable.Empty<Diagnostic>()).ToList();
    if (result.IsValid && diagnostics.Count == 0)
    {
        Console.WriteLine($"ok    {rel}");
        continue;
    }

    failed++;
    Console.WriteLine($"FAIL  {rel}");
    foreach (var d in diagnostics)
    {
        Console.WriteLine($"        {d}");
    }
}

Console.WriteLine();
Console.WriteLine($"{files.Count} queries checked: {files.Count - failed} valid, {failed} failed");
return failed == 0 ? 0 : 1;

/// <summary>Built-in Sentinel tables, with local JSON schemas overriding tables of the same name.</summary>
sealed class LocalOverrideTablesLoader : ITableSchemasLoader
{
    private readonly string _path;
    public LocalOverrideTablesLoader(string path) => _path = path;

    public IEnumerable<TableSchema> Load()
    {
        var custom = new CustomJsonDirectoryTablesLoader(_path).Load().ToList();
        var names = custom.Select(t => t.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
        return new SentinelDefaultTablesLoader().Load().Where(t => !names.Contains(t.Name)).Concat(custom);
    }
}
