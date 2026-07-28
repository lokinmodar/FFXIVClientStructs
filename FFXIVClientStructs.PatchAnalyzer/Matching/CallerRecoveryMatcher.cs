using System.Collections.Immutable;
using FFXIVClientStructs.PatchAnalyzer.Analysis;
using FFXIVClientStructs.PatchAnalyzer.Binary;
using FFXIVClientStructs.PatchAnalyzer.Data;
using FFXIVClientStructs.PatchAnalyzer.Graph;

namespace FFXIVClientStructs.PatchAnalyzer.Matching;

/// <summary>Provides caller anchors and fingerprint settings for one-hop target recovery.</summary>
public sealed record CallerRecoveryContext(
    int CallSiteInstructionRadius,
    IReadOnlyDictionary<Rva, FunctionMatchResult> FunctionMatches,
    IReadOnlyDictionary<Rva, SymbolAnalysis> SignedCallerAnchors);

/// <summary>Recovers missing function targets from uniquely mapped callers and normalized call-sites.</summary>
public static class CallerRecoveryMatcher {
    /// <summary>Attempts one-hop caller recovery for a non-direct function result.</summary>
    /// <param name="directResult">The direct matching result for the target symbol.</param>
    /// <param name="previous">The previous-version call graph.</param>
    /// <param name="current">The current-version call graph.</param>
    /// <param name="context">The exact caller matches and signed caller anchors.</param>
    /// <returns>The direct result updated with caller-recovery evidence or an explainable non-acceptance status.</returns>
    public static SymbolAnalysis Recover(
        SymbolAnalysis directResult,
        CallGraph previous,
        CallGraph current,
        CallerRecoveryContext context) {
        ArgumentNullException.ThrowIfNull(directResult);
        ArgumentNullException.ThrowIfNull(previous);
        ArgumentNullException.ThrowIfNull(current);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(context.FunctionMatches);
        ArgumentNullException.ThrowIfNull(context.SignedCallerAnchors);
        ArgumentOutOfRangeException.ThrowIfNegative(context.CallSiteInstructionRadius);

        if (directResult.Status is not (SymbolStatus.Missing or SymbolStatus.Ambiguous))
            return directResult;
        if (directResult.LocationKind != LocationKind.Function)
            return With(directResult, SymbolStatus.Unsupported, null, [], "Caller recovery only supports function locations.");
        if (directResult.PreviousDataRva is not { } previousTarget)
            return With(directResult, SymbolStatus.Unsupported, null, [], "Caller recovery requires a previous function RVA.");

        var incoming = previous.FindIncoming(previousTarget)
            .OrderBy(edge => edge.SourceFunction.Value)
            .ThenBy(edge => edge.CallSite.Value)
            .ThenBy(edge => edge.Kind)
            .ToImmutableArray();
        if (incoming.IsEmpty)
            return directResult;

        var evidence = ImmutableArray.CreateBuilder<RecoveryEvidence>();
        var hasNonAcceptingCallerMapping = false;
        var hasUnsupportedCaller = false;
        var hasUnmatchedCurrentCall = false;
        var hasCompetingCallSite = false;

        foreach (var edge in incoming) {
            var previousFunction = FindFunction(previous, edge.SourceFunction);
            if (previousFunction is null || previousFunction.IsSuspect) {
                hasUnsupportedCaller = true;
                continue;
            }

            if (!TryMapCaller(edge.SourceFunction, context, out var currentCaller, out var anchorKind, out var isFuzzy)) {
                hasNonAcceptingCallerMapping |= isFuzzy;
                continue;
            }

            var currentFunction = FindFunction(current, currentCaller);
            if (currentFunction is null || currentFunction.IsSuspect) {
                hasUnsupportedCaller = true;
                continue;
            }

            var previousFingerprint = CallSiteFingerprint.Create(previousFunction, edge.CallSite, context.CallSiteInstructionRadius);
            var matchingEdges = current.DirectCalls
                .Where(candidate => candidate.SourceFunction == currentCaller)
                .Where(candidate => candidate.Kind == edge.Kind)
                .Where(candidate => CallSiteFingerprint.Create(currentFunction, candidate.CallSite, context.CallSiteInstructionRadius).Sha256 == previousFingerprint.Sha256)
                .OrderBy(candidate => candidate.CallSite.Value)
                .ThenBy(candidate => candidate.Target.Value)
                .ToImmutableArray();

            if (matchingEdges.IsEmpty) {
                hasUnmatchedCurrentCall = true;
                continue;
            }
            if (matchingEdges.Length != 1) {
                hasCompetingCallSite = true;
                continue;
            }

            var match = matchingEdges[0];
            evidence.Add(new RecoveryEvidence(
                anchorKind,
                previousTarget,
                match.Target,
                edge.SourceFunction,
                edge.CallSite,
                currentCaller,
                match.CallSite,
                previousFingerprint.Sha256));
        }

        if (hasCompetingCallSite || hasNonAcceptingCallerMapping)
            return With(directResult, SymbolStatus.Ambiguous, null, [], hasNonAcceptingCallerMapping
                ? "A caller does not have an exact unique structural mapping."
                : "Multiple current call-sites have the same normalized fingerprint.");

        var targets = evidence.Select(item => item.CurrentTarget).Distinct().OrderBy(target => target.Value).ToImmutableArray();
        if (targets.Length > 1)
            return With(directResult, SymbolStatus.Ambiguous, null, [], "Independent caller anchors resolve to different targets.");
        if (targets.Length == 1)
            return With(directResult, SymbolStatus.CallerRecovered, targets[0], evidence.ToImmutable(), null);
        if (hasUnmatchedCurrentCall)
            return With(directResult, SymbolStatus.PossibleInlining, null, [], "Previous direct callers have no equivalent current direct call-site.");
        if (hasUnsupportedCaller)
            return With(directResult, SymbolStatus.Unsupported, null, [], "Only suspect or unsupported caller evidence is available.");
        return directResult;
    }

    private static bool TryMapCaller(
        Rva previousCaller,
        CallerRecoveryContext context,
        out Rva currentCaller,
        out string anchorKind,
        out bool isFuzzy) {
        if (context.SignedCallerAnchors.TryGetValue(previousCaller, out var signedAnchor) &&
            signedAnchor.Status == SymbolStatus.DirectUnique &&
            signedAnchor.PreviousDataRva == previousCaller &&
            signedAnchor.CurrentTarget is { } signedCurrent) {
            currentCaller = signedCurrent;
            anchorKind = "SignedCaller";
            isFuzzy = false;
            return true;
        }

        if (context.FunctionMatches.TryGetValue(previousCaller, out var structuralMatch)) {
            if (structuralMatch.Status == SymbolStatus.StructuralRecovered && structuralMatch.CurrentTarget is { } structuralCurrent) {
                currentCaller = structuralCurrent;
                anchorKind = "StructuralCaller";
                isFuzzy = false;
                return true;
            }

            isFuzzy = structuralMatch.Status == SymbolStatus.Ambiguous ||
                      structuralMatch.Candidates.Any(candidate => !candidate.Exact);
        } else {
            isFuzzy = false;
        }

        currentCaller = default;
        anchorKind = string.Empty;
        return false;
    }

    private static FunctionGraph? FindFunction(CallGraph graph, Rva begin) =>
        graph.Functions.FirstOrDefault(function => function.Range.Begin == begin);

    private static SymbolAnalysis With(
        SymbolAnalysis source,
        SymbolStatus status,
        Rva? currentTarget,
        ImmutableArray<RecoveryEvidence> evidence,
        string? diagnostic) => source with {
            Status = status,
            CurrentTarget = currentTarget,
            RecoveryEvidence = evidence,
            SuggestedSignature = null,
            Diagnostics = diagnostic is null ? [] : [diagnostic]
        };
}
