namespace FFXIVClientStructs.PatchAnalyzer.Analysis;

public sealed record AnalysisConfiguration(
    int MatchLimit,
    int MaximumSignatureBytes,
    int CallSiteInstructionRadius,
    string? PreviousVersionOverride,
    string? CurrentVersionOverride);
