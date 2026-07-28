using System.Collections.Immutable;
using FFXIVClientStructs.PatchAnalyzer.Binary;
using FFXIVClientStructs.PatchAnalyzer.Data;
using FFXIVClientStructs.PatchAnalyzer.Signatures;

namespace FFXIVClientStructs.PatchAnalyzer.Analysis;

public enum SymbolStatus {
    DirectUnique, StructuralRecovered, CallerRecovered, StaleSource, Ambiguous, Missing,
    PossibleInlining, NotInData, Unsupported, AnalysisError
}

public sealed record RecoveryEvidence(
    string AnchorKind,
    Rva PreviousTarget,
    Rva CurrentTarget,
    Rva? PreviousCaller,
    Rva? PreviousCallSite,
    Rva? CurrentCaller,
    Rva? CurrentCallSite,
    string FingerprintSha256);

public sealed record SignatureProposal(
    string PatternText,
    ImmutableArray<ushort> RelativeFollowOffsets,
    Rva PatternRva,
    Rva ResolvedRva,
    int ByteLength,
    string Source);

public sealed record SymbolAnalysis(
    string GeneratedName,
    string? NativeName,
    LocationKind? LocationKind,
    SignatureDefinition Signature,
    Rva? PreviousDataRva,
    SignatureScanResult PreviousScan,
    SignatureScanResult CurrentScan,
    SymbolStatus Status,
    Rva? CurrentTarget,
    ImmutableArray<RecoveryEvidence> RecoveryEvidence,
    SignatureProposal? SuggestedSignature,
    ImmutableArray<string> Diagnostics);
