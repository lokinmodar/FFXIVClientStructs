using System.Collections.Immutable;
using FFXIVClientStructs.PatchAnalyzer.Analysis;
using FFXIVClientStructs.PatchAnalyzer.Data;
using FFXIVClientStructs.PatchAnalyzer.Signatures;

namespace FFXIVClientStructs.PatchAnalyzer.Matching;

public static class DirectMatcher {
    public static SymbolAnalysis Match(
        SignatureCatalogEntry entry,
        SignatureScanResult previousScan,
        SignatureScanResult currentScan) {
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentNullException.ThrowIfNull(previousScan);
        ArgumentNullException.ThrowIfNull(currentScan);

        var (status, currentTarget, diagnostic) = Classify(entry, previousScan, currentScan);
        return new SymbolAnalysis(
            entry.Signature.GeneratedName,
            entry.Location?.NativeName,
            entry.Location?.Kind,
            entry.Signature,
            entry.Location?.Rva,
            previousScan,
            currentScan,
            status,
            currentTarget,
            [],
            null,
            diagnostic is null ? [] : [diagnostic]);
    }

    private static (SymbolStatus Status, Binary.Rva? CurrentTarget, string? Diagnostic) Classify(
        SignatureCatalogEntry entry,
        SignatureScanResult previousScan,
        SignatureScanResult currentScan) {
        if (entry.CorrelationStatus == DataCorrelationStatus.Missing)
            return (SymbolStatus.NotInData, null, entry.Diagnostic ?? "The signature has no matching data.yml entry.");
        if (entry.CorrelationStatus == DataCorrelationStatus.Ambiguous)
            return (SymbolStatus.Ambiguous, null, entry.Diagnostic ?? "The signature matches multiple data.yml entries.");
        if (entry.CorrelationStatus == DataCorrelationStatus.Invalid)
            return (SymbolStatus.AnalysisError, null, entry.Diagnostic ?? "The signature cannot be correlated to data.yml.");
        if (entry.Location is null)
            return (SymbolStatus.NotInData, null, "The matched data.yml entry has no mapped RVA.");
        if (previousScan.Truncated)
            return (SymbolStatus.AnalysisError, null, "Previous scan reached its match limit.");
        if (previousScan.Matches.Length != 1 || previousScan.Matches[0].ResolvedRva != entry.Location.Rva)
            return (SymbolStatus.StaleSource, null, "Previous scan does not uniquely resolve to the data.yml RVA.");

        return CandidateClassifier.Classify(currentScan);
    }
}
