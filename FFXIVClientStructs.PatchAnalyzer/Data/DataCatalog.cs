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
        if (yaml.Documents.Count != 1 || yaml.Documents[0].RootNode is not YamlMappingNode root)
            throw new FormatException("data.yml must contain one mapping document.");

        ValidateShape(root);

        var sourceMap = DataSourceMap.Scan(sourceText, previousImageBase);
        return new DataCatalog(sourceText, sourceMap.Version, sourceMap.VersionSourceSpan, sourceMap.Locations);
    }

    private static void ValidateShape(YamlMappingNode root) {
        RequireScalar(root, "version");
        ValidateScalarMapping(RequireMapping(root, "globals"), "globals");
        ValidateScalarMapping(RequireMapping(root, "functions"), "functions");

        foreach (var (classKey, classValue) in RequireMapping(root, "classes").Children) {
            if (classKey is not YamlScalarNode || classValue is not YamlMappingNode classMapping)
                throw new FormatException("classes must map scalar names to mappings.");

            if (TryGet(classMapping, "funcs", out var funcs))
                ValidateScalarMapping(RequireMapping(funcs, "class funcs"), "class funcs");
            if (TryGet(classMapping, "instances", out var instances))
                ValidateAddressSequence(RequireSequence(instances, "instances"), "instances");
            if (TryGet(classMapping, "vtbls", out var vtbls))
                ValidateAddressSequence(RequireSequence(vtbls, "vtbls"), "vtbls");
        }
    }

    private static void ValidateScalarMapping(YamlMappingNode mapping, string name) {
        if (mapping.Children.Any(pair => pair.Key is not YamlScalarNode || pair.Value is not YamlScalarNode))
            throw new FormatException($"{name} must map scalar values.");
    }

    private static void ValidateAddressSequence(YamlSequenceNode sequence, string name) {
        foreach (var entry in sequence.Children) {
            if (entry is not YamlMappingNode mapping || !TryGet(mapping, "ea", out var address) || address is not YamlScalarNode)
                throw new FormatException($"{name} entries must map ea to a scalar value.");
        }
    }

    private static YamlMappingNode RequireMapping(YamlMappingNode parent, string name) {
        if (!TryGet(parent, name, out var value))
            throw new FormatException($"{name} must be a mapping.");
        return RequireMapping(value, name);
    }

    private static YamlMappingNode RequireMapping(YamlNode node, string name) {
        if (node is not YamlMappingNode mapping)
            throw new FormatException($"{name} must be a mapping.");
        return mapping;
    }

    private static YamlSequenceNode RequireSequence(YamlNode node, string name) {
        if (node is not YamlSequenceNode sequence)
            throw new FormatException($"{name} must be a sequence.");
        return sequence;
    }

    private static void RequireScalar(YamlMappingNode parent, string name) {
        if (!TryGet(parent, name, out var value) || value is not YamlScalarNode)
            throw new FormatException($"{name} must be a scalar.");
    }

    private static bool TryGet(YamlMappingNode parent, string name, out YamlNode value) {
        foreach (var (key, candidate) in parent.Children) {
            if (key is YamlScalarNode { Value: var keyName } && keyName == name) {
                value = candidate;
                return true;
            }
        }

        value = null!;
        return false;
    }
}
