using System.Collections.Immutable;
using YamlDotNet.Core;
using YamlDotNet.Core.Events;

namespace FFXIVClientStructs.PatchAnalyzer.Data;

internal sealed class YamlDuplicateKeyMap {
    private YamlDuplicateKeyMap(bool hasDuplicateClassDeclarations, bool hasOtherDuplicateKeys) {
        HasOnlyDuplicateClassDeclarations = hasDuplicateClassDeclarations && !hasOtherDuplicateKeys;
    }

    public bool HasOnlyDuplicateClassDeclarations { get; }

    public static YamlDuplicateKeyMap Scan(string sourceText) {
        using var reader = new StringReader(sourceText);
        var parser = new Parser(reader);
        var hasDuplicateClassDeclarations = false;
        var hasOtherDuplicateKeys = false;

        if (!parser.MoveNext() || parser.Current is not StreamStart)
            return new YamlDuplicateKeyMap(false, true);

        parser.MoveNext();
        var documentCount = 0;
        while (parser.Current is DocumentStart) {
            documentCount++;
            parser.MoveNext();
            ScanNode(parser, [], ref hasDuplicateClassDeclarations, ref hasOtherDuplicateKeys);
            if (parser.Current is not DocumentEnd)
                return new YamlDuplicateKeyMap(false, true);
            parser.MoveNext();
        }

        if (documentCount != 1 || parser.Current is not StreamEnd)
            hasOtherDuplicateKeys = true;

        return new YamlDuplicateKeyMap(hasDuplicateClassDeclarations, hasOtherDuplicateKeys);
    }

    private static void ScanNode(
        IParser parser,
        ImmutableArray<string> path,
        ref bool hasDuplicateClassDeclarations,
        ref bool hasOtherDuplicateKeys) {
        switch (parser.Current) {
            case Scalar:
            case AnchorAlias:
                parser.MoveNext();
                return;
            case SequenceStart:
                parser.MoveNext();
                while (parser.Current is not SequenceEnd)
                    ScanNode(parser, path, ref hasDuplicateClassDeclarations, ref hasOtherDuplicateKeys);
                parser.MoveNext();
                return;
            case MappingStart:
                ScanMapping(parser, path, ref hasDuplicateClassDeclarations, ref hasOtherDuplicateKeys);
                return;
            default:
                hasOtherDuplicateKeys = true;
                parser.MoveNext();
                return;
        }
    }

    private static void ScanMapping(
        IParser parser,
        ImmutableArray<string> path,
        ref bool hasDuplicateClassDeclarations,
        ref bool hasOtherDuplicateKeys) {
        var keys = new HashSet<string>(StringComparer.Ordinal);
        parser.MoveNext();

        while (parser.Current is not MappingEnd) {
            if (parser.Current is not Scalar key) {
                hasOtherDuplicateKeys = true;
                ScanNode(parser, path, ref hasDuplicateClassDeclarations, ref hasOtherDuplicateKeys);
                ScanNode(parser, path, ref hasDuplicateClassDeclarations, ref hasOtherDuplicateKeys);
                continue;
            }

            parser.MoveNext();
            if (!keys.Add(key.Value)) {
                if (path is ["classes"])
                    hasDuplicateClassDeclarations = true;
                else
                    hasOtherDuplicateKeys = true;
            }

            ScanNode(parser, path.Add(key.Value), ref hasDuplicateClassDeclarations, ref hasOtherDuplicateKeys);
        }

        parser.MoveNext();
    }
}
