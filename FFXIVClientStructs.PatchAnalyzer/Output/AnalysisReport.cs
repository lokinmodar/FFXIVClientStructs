using System.Collections.Immutable;
using FFXIVClientStructs.PatchAnalyzer.Analysis;
using FFXIVClientStructs.PatchAnalyzer.Binary;
using FFXIVClientStructs.PatchAnalyzer.Data;

namespace FFXIVClientStructs.PatchAnalyzer.Output;

/// <summary>Represents the schema-versioned deterministic JSON report.</summary>
public sealed record AnalysisReport(
    int SchemaVersion,
    string RunStatus,
    string ToolVersion,
    string RepositoryVersion,
    ArtifactNames Artifacts,
    ReportBinary PreviousBinary,
    ReportBinary CurrentBinary,
    AnalysisConfiguration Configuration,
    ImmutableSortedDictionary<string, long> WorkloadCounts,
    ImmutableSortedDictionary<string, long> StatusCounts,
    ImmutableArray<ReportSymbol> Symbols) {
    /// <summary>Creates a report projection that excludes non-deterministic timing data.</summary>
    /// <param name="result">The analysis result to project.</param>
    /// <returns>A deterministic report projection.</returns>
    public static AnalysisReport Create(PatchAnalysisResult result) {
        ArgumentNullException.ThrowIfNull(result);

        var symbols = result.Symbols
            .OrderBy(symbol => symbol.GeneratedName, StringComparer.Ordinal)
            .Select(symbol => ReportSymbol.Create(symbol, result.Data))
            .ToImmutableArray();
        var statusCounts = symbols
            .GroupBy(symbol => symbol.Status)
            .ToImmutableSortedDictionary(group => ToSnakeCase(group.Key), group => (long)group.Count(), StringComparer.Ordinal);

        return new AnalysisReport(
            1,
            result.RunStatus,
            result.ToolVersion,
            result.RepositoryVersion,
            new ArtifactNames("report.json", "data.candidate.yml"),
            ReportBinary.Create(result.PreviousBinary),
            ReportBinary.Create(result.CurrentBinary),
            result.Configuration,
            result.WorkloadCounts,
            statusCounts,
            symbols);
    }

    internal static string ToSnakeCase<TEnum>(TEnum value) where TEnum : struct, Enum => string.Concat(value.ToString().Select((character, index) => index > 0 && char.IsUpper(character) ? $"_{char.ToLowerInvariant(character)}" : char.ToLowerInvariant(character).ToString()));
}

/// <summary>Names the relative artifacts emitted for an analysis run.</summary>
public sealed record ArtifactNames(string Report, string CandidateYaml);

/// <summary>Describes an executable without including its local path.</summary>
public sealed record ReportBinary(string FileName, long Length, string Sha256, string? GameVersion, string VersionSource) {
    internal static ReportBinary Create(BinaryIdentity identity) => new(identity.FileName, identity.Length, identity.Sha256, identity.GameVersion, identity.VersionSource);
}

/// <summary>Describes one analyzed symbol in the deterministic report.</summary>
public sealed record ReportSymbol(
    string GeneratedName,
    string? NativeName,
    LocationKind? LocationKind,
    string Pattern,
    ImmutableArray<ushort> RelativeFollowOffsets,
    ulong? PreviousDataPreferredVa,
    uint? PreviousDataRva,
    ReportScan PreviousScan,
    ReportScan CurrentScan,
    SymbolStatus Status,
    uint? CurrentTargetRva,
    ImmutableArray<ReportRecoveryEvidence> RecoveryEvidence,
    ReportSignatureProposal? SuggestedSignature,
    ImmutableArray<string> Diagnostics) {
    internal static ReportSymbol Create(SymbolAnalysis symbol, DataCatalog data) => new(
        symbol.GeneratedName,
        symbol.NativeName,
        symbol.LocationKind,
        symbol.Signature.PatternText,
        symbol.Signature.RelativeFollowOffsets,
        symbol.PreviousDataRva is { } previousDataRva
            ? data.Locations.Where(location => location.Rva == previousDataRva).Select(location => (ulong?)location.PreferredVa.Value).FirstOrDefault()
            : null,
        symbol.PreviousDataRva?.Value,
        ReportScan.Create(symbol.PreviousScan),
        ReportScan.Create(symbol.CurrentScan),
        symbol.Status,
        symbol.CurrentTarget?.Value,
        symbol.RecoveryEvidence
            .OrderBy(evidence => evidence.PreviousCallSite?.Value)
            .ThenBy(evidence => evidence.CurrentCallSite?.Value)
            .ThenBy(evidence => evidence.AnchorKind, StringComparer.Ordinal)
            .Select(ReportRecoveryEvidence.Create)
            .ToImmutableArray(),
        symbol.SuggestedSignature is { } proposal ? ReportSignatureProposal.Create(proposal) : null,
        symbol.Diagnostics.Order(StringComparer.Ordinal).ToImmutableArray());
}

/// <summary>Describes sorted scan results for a symbol.</summary>
public sealed record ReportScan(ImmutableArray<ReportMatch> Matches, bool Truncated, ImmutableArray<string> Diagnostics) {
    internal static ReportScan Create(Signatures.SignatureScanResult scan) => new(
        scan.Matches.OrderBy(match => match.PatternRva.Value).ThenBy(match => match.ResolvedRva.Value).Select(match => new ReportMatch(match.PatternRva.Value, match.ResolvedRva.Value)).ToImmutableArray(),
        scan.Truncated,
        scan.Diagnostics.Order(StringComparer.Ordinal).ToImmutableArray());
}

/// <summary>Describes one resolved signature match.</summary>
public sealed record ReportMatch(uint PatternRva, uint ResolvedRva);

/// <summary>Describes evidence supporting a recovered symbol.</summary>
public sealed record ReportRecoveryEvidence(
    string AnchorKind,
    bool Accepted,
    uint PreviousTargetRva,
    uint? CurrentTargetRva,
    uint? PreviousCallerRva,
    uint? PreviousCallSiteRva,
    uint? CurrentCallerRva,
    uint? CurrentCallSiteRva,
    string? FingerprintSha256,
    ImmutableArray<string> FingerprintInputs,
    ImmutableArray<ReportRecoveryCandidateEvidence> ConsideredCandidates,
    string? RejectionReason) {
    internal static ReportRecoveryEvidence Create(RecoveryEvidence evidence) => new(
        evidence.AnchorKind,
        evidence.Accepted,
        evidence.PreviousTarget.Value,
        evidence.CurrentTarget?.Value,
        evidence.PreviousCaller?.Value,
        evidence.PreviousCallSite?.Value,
        evidence.CurrentCaller?.Value,
        evidence.CurrentCallSite?.Value,
        evidence.FingerprintSha256,
        evidence.FingerprintInputs,
        evidence.ConsideredCandidates
            .OrderBy(candidate => candidate.CurrentCaller?.Value)
            .ThenBy(candidate => candidate.CurrentCallSite?.Value)
            .ThenBy(candidate => candidate.CurrentTarget?.Value)
            .ThenBy(candidate => candidate.Rank)
            .Select(ReportRecoveryCandidateEvidence.Create)
            .ToImmutableArray(),
        evidence.RejectionReason);
}

/// <summary>Describes one candidate considered while evaluating recovery evidence.</summary>
public sealed record ReportRecoveryCandidateEvidence(
    uint? CurrentTargetRva,
    uint? CurrentCallerRva,
    uint? CurrentCallSiteRva,
    bool Exact,
    int Rank,
    string? FingerprintSha256,
    string? RejectionReason) {
    internal static ReportRecoveryCandidateEvidence Create(RecoveryCandidateEvidence evidence) => new(
        evidence.CurrentTarget?.Value,
        evidence.CurrentCaller?.Value,
        evidence.CurrentCallSite?.Value,
        evidence.Exact,
        evidence.Rank,
        evidence.FingerprintSha256,
        evidence.RejectionReason);
}

/// <summary>Describes a synthesized signature proposed for review.</summary>
public sealed record ReportSignatureProposal(string Pattern, ImmutableArray<ushort> RelativeFollowOffsets, uint PatternRva, uint ResolvedRva, int ByteLength, string Source) {
    internal static ReportSignatureProposal Create(SignatureProposal proposal) => new(proposal.PatternText, proposal.RelativeFollowOffsets, proposal.PatternRva.Value, proposal.ResolvedRva.Value, proposal.ByteLength, proposal.Source);
}
