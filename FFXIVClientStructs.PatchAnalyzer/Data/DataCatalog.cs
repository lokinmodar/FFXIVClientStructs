using System.Collections.Immutable;
using FFXIVClientStructs.PatchAnalyzer.Binary;
using YamlDotNet.RepresentationModel;

namespace FFXIVClientStructs.PatchAnalyzer.Data;

public enum LocationKind { Function, Instance, VirtualTable, Global }

public sealed record DataLocation(
    string NativeName,
    LocationKind Kind,
    PreferredVa PreferredVa,
    Rva Rva,
    SourceSpan SourceSpan);

public sealed class DataCatalog {
    private DataCatalog(string sourceText, string version, SourceSpan versionSourceSpan, ImmutableArray<DataLocation> locations) {
        SourceText = sourceText;
        Version = version;
        VersionSourceSpan = versionSourceSpan;
        Locations = locations;
    }

    public string SourceText { get; }
    public string Version { get; }
    public SourceSpan VersionSourceSpan { get; }
    public ImmutableArray<DataLocation> Locations { get; }

    public static DataCatalog Parse(string sourceText, ulong previousImageBase) {
        ArgumentNullException.ThrowIfNull(sourceText);

        using var reader = new StringReader(sourceText);
        var yaml = new YamlStream();
        yaml.Load(reader);
        if (yaml.Documents.Count != 1 || yaml.Documents[0].RootNode is not YamlMappingNode)
            throw new FormatException("data.yml must contain one mapping document.");

        var sourceMap = DataSourceMap.Scan(sourceText, previousImageBase);
        return new DataCatalog(sourceText, sourceMap.Version, sourceMap.VersionSourceSpan, sourceMap.Locations);
    }
}
