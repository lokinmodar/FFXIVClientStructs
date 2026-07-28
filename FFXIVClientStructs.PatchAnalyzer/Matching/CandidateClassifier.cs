using FFXIVClientStructs.PatchAnalyzer.Analysis;
using FFXIVClientStructs.PatchAnalyzer.Binary;
using FFXIVClientStructs.PatchAnalyzer.Decoding;
using FFXIVClientStructs.PatchAnalyzer.Signatures;

namespace FFXIVClientStructs.PatchAnalyzer.Matching;

public static class CandidateClassifier {
    public static (SymbolStatus Status, Rva? CurrentTarget, string? Diagnostic) Classify(SignatureScanResult currentScan) {
        if (currentScan.Truncated)
            return (SymbolStatus.Ambiguous, null, "Current scan reached its match limit.");

        return currentScan.Matches.Length switch {
            0 => (SymbolStatus.Missing, null, "The signature has no current matches."),
            1 => (SymbolStatus.DirectUnique, currentScan.Matches[0].ResolvedRva, null),
            _ => (SymbolStatus.Ambiguous, null, "The signature has multiple current matches.")
        };
    }

    public static SymbolAnalysis RevalidateRecovered(
        SymbolAnalysis analysis,
        PeImage image,
        FunctionIndex functionIndex,
        IInstructionDecoder decoder) {
        ArgumentNullException.ThrowIfNull(analysis);
        ArgumentNullException.ThrowIfNull(image);
        ArgumentNullException.ThrowIfNull(functionIndex);
        ArgumentNullException.ThrowIfNull(decoder);

        if (analysis.Status is not (SymbolStatus.StructuralRecovered or SymbolStatus.CallerRecovered))
            return analysis;

        if (analysis.CurrentTarget is not { } recoveredTarget)
            return Downgrade(analysis, null);

        var synthesizer = new SignatureSynthesizer(functionIndex, decoder);
        var proposal = synthesizer.Synthesize(image, recoveredTarget, null) ??
            analysis.RecoveryEvidence
                .Where(evidence => evidence.CurrentTarget == recoveredTarget && evidence.CurrentCallSite is not null)
                .Select(evidence => evidence.CurrentCallSite!.Value)
                .Distinct()
                .OrderBy(callSite => callSite.Value)
                .Select(callSite => synthesizer.Synthesize(image, recoveredTarget, callSite))
                .FirstOrDefault(candidate => candidate is not null);

        return proposal is null
            ? Downgrade(analysis, recoveredTarget)
            : analysis with { SuggestedSignature = proposal };
    }

    private static SymbolAnalysis Downgrade(SymbolAnalysis analysis, Rva? recoveredTarget) {
        var (status, _, diagnostic) = Classify(analysis.CurrentScan);
        var downgradedStatus = status == SymbolStatus.Missing ? SymbolStatus.Missing : SymbolStatus.Ambiguous;
        var diagnostics = analysis.Diagnostics.ToList();
        if (recoveredTarget is { } target)
            diagnostics.Add($"Recovered target 0x{target.Value:X} could not be revalidated by a unique signature.");
        if (diagnostic is not null)
            diagnostics.Add(diagnostic);

        return analysis with {
            Status = downgradedStatus,
            CurrentTarget = null,
            SuggestedSignature = null,
            Diagnostics = [.. diagnostics]
        };
    }
}
