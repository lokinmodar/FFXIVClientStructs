using System.Collections.Immutable;

namespace FFXIVClientStructs.PatchAnalyzer.Signatures;

public sealed record SignatureDefinition(
    string GeneratedName,
    string PatternText,
    SignaturePattern Pattern,
    ImmutableArray<ushort> RelativeFollowOffsets) {
    public static SignatureDefinition Parse(
        string generatedName,
        string patternText,
        IEnumerable<ushort> relativeFollowOffsets) {
        ArgumentException.ThrowIfNullOrWhiteSpace(generatedName);
        ArgumentNullException.ThrowIfNull(relativeFollowOffsets);

        var pattern = SignaturePattern.Parse(patternText);
        return new SignatureDefinition(
            generatedName,
            pattern.ToString(),
            pattern,
            relativeFollowOffsets.ToImmutableArray());
    }
}
