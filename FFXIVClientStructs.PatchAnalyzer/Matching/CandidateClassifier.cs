using FFXIVClientStructs.PatchAnalyzer.Analysis;
using FFXIVClientStructs.PatchAnalyzer.Binary;
using FFXIVClientStructs.PatchAnalyzer.Signatures;

namespace FFXIVClientStructs.PatchAnalyzer.Matching;

internal static class CandidateClassifier {
    public static (SymbolStatus Status, Rva? CurrentTarget, string? Diagnostic) Classify(SignatureScanResult currentScan) {
        if (currentScan.Truncated)
            return (SymbolStatus.Ambiguous, null, "Current scan reached its match limit.");

        return currentScan.Matches.Length switch {
            0 => (SymbolStatus.Missing, null, "The signature has no current matches."),
            1 => (SymbolStatus.DirectUnique, currentScan.Matches[0].ResolvedRva, null),
            _ => (SymbolStatus.Ambiguous, null, "The signature has multiple current matches.")
        };
    }
}
