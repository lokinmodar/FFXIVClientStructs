using System.Collections.Immutable;
using FFXIVClientStructs.PatchAnalyzer.Signatures;

namespace FFXIVClientStructs.PatchAnalyzer.Data;

public enum DataCorrelationStatus { Matched, Missing, Ambiguous, Invalid }

public sealed record SignatureCatalogEntry(
    SignatureDefinition Signature,
    DataCorrelationStatus CorrelationStatus,
    DataLocation? Location,
    string? Diagnostic);

public static class SignatureCorrelator {
    private const string GeneratedPrefix = "FFXIVClientStructs.FFXIV.";

    public static ImmutableArray<SignatureCatalogEntry> Correlate(
        IReadOnlyList<SignatureDefinition> signatures,
        DataCatalog catalog) {
        ArgumentNullException.ThrowIfNull(signatures);
        ArgumentNullException.ThrowIfNull(catalog);

        return signatures.Select(signature => Correlate(signature, catalog)).ToImmutableArray();
    }

    private static SignatureCatalogEntry Correlate(SignatureDefinition signature, DataCatalog catalog) {
        if (!signature.GeneratedName.StartsWith(GeneratedPrefix, StringComparison.Ordinal))
            return new SignatureCatalogEntry(signature, DataCorrelationStatus.Invalid, null, "Generated name does not use the FFXIV namespace prefix.");

        var generatedName = signature.GeneratedName[GeneratedPrefix.Length..];
        if (generatedName.StartsWith("Havok.", StringComparison.Ordinal))
            return new SignatureCatalogEntry(signature, DataCorrelationStatus.Missing, null, "Havok signatures are not represented in data.yml.");

        var lastDot = generatedName.LastIndexOf('.');
        if (lastDot < 1 || lastDot == generatedName.Length - 1)
            return new SignatureCatalogEntry(signature, DataCorrelationStatus.Invalid, null, "Generated name does not identify a member.");

        var nativeType = string.Join("::", generatedName[..lastDot].Split('.'));
        var member = generatedName[(lastDot + 1)..];
        var kind = LocationKind.Function;
        string nativeName;

        if (member == "Instance") {
            nativeName = nativeType;
            kind = LocationKind.Instance;
        } else if (member == "StaticVirtualTable") {
            nativeName = nativeType;
            kind = LocationKind.VirtualTable;
        } else {
            if (member.StartsWith("Ctor", StringComparison.Ordinal) || member.StartsWith("Dtor", StringComparison.Ordinal))
                member = char.ToLowerInvariant(member[0]) + member[1..];
            nativeName = $"{nativeType}::{member}";
        }

        var candidates = catalog.Locations
            .Where(location => location.Kind == kind && location.NativeName == nativeName)
            .ToArray();

        if (candidates.Length == 0 && kind == LocationKind.Function)
            candidates = catalog.Locations
                .Where(location => location.Kind == LocationKind.Global && location.NativeName == $"g_{nativeName}")
                .ToArray();

        if (candidates.Length == 0)
            return new SignatureCatalogEntry(signature, DataCorrelationStatus.Missing, null, $"No {kind} entry matches '{nativeName}'.");
        if (candidates.Length != 1 || candidates.Select(location => location.SourceSpan).Distinct().Count() != 1)
            return new SignatureCatalogEntry(signature, DataCorrelationStatus.Ambiguous, null, $"Multiple data.yml entries match '{nativeName}'.");

        return new SignatureCatalogEntry(signature, DataCorrelationStatus.Matched, candidates[0], null);
    }
}
