using System.Collections.Immutable;
using FFXIVClientStructs.PatchAnalyzer.Analysis;
using FFXIVClientStructs.PatchAnalyzer.Binary;
using FFXIVClientStructs.PatchAnalyzer.Data;
using FFXIVClientStructs.PatchAnalyzer.Decoding;
using FFXIVClientStructs.PatchAnalyzer.Graph;

namespace FFXIVClientStructs.PatchAnalyzer.Matching;

/// <summary>Provides caller anchors and fingerprint settings for one-hop target recovery.</summary>
public sealed record CallerRecoveryContext {
    /// <summary>Initializes a new instance of the <see cref="CallerRecoveryContext"/> class.</summary>
    /// <param name="callSiteInstructionRadius">The required count of decoded instructions on each side of a call-site.</param>
    /// <param name="functionMatches">The exact Task 9 function matches indexed by previous function RVA.</param>
    /// <param name="signedCallerAnchors">The direct signature results indexed by previous caller RVA.</param>
    /// <param name="previousImage">The previous image used for trusted-seed decoding and fingerprint normalization.</param>
    /// <param name="currentImage">The current image used for trusted-seed decoding and fingerprint normalization.</param>
    /// <param name="decoder">The instruction decoder used for trusted-seed bounded decoding.</param>
    public CallerRecoveryContext(
        int callSiteInstructionRadius,
        IReadOnlyDictionary<Rva, FunctionMatchResult> functionMatches,
        IReadOnlyDictionary<Rva, SymbolAnalysis> signedCallerAnchors,
        PeImage previousImage,
        PeImage currentImage,
        IInstructionDecoder decoder) {
        if (callSiteInstructionRadius != CallSiteFingerprint.InstructionRadius)
            throw new ArgumentOutOfRangeException(nameof(callSiteInstructionRadius), callSiteInstructionRadius, "The call-site instruction radius must be exactly four.");

        ArgumentNullException.ThrowIfNull(functionMatches);
        ArgumentNullException.ThrowIfNull(signedCallerAnchors);
        ArgumentNullException.ThrowIfNull(previousImage);
        ArgumentNullException.ThrowIfNull(currentImage);
        ArgumentNullException.ThrowIfNull(decoder);
        FunctionMatches = functionMatches;
        SignedCallerAnchors = signedCallerAnchors;
        PreviousImage = previousImage;
        CurrentImage = currentImage;
        Decoder = decoder;
        CallSiteInstructionRadius = callSiteInstructionRadius;
    }

    /// <summary>Gets the required count of decoded instructions on each side of a call-site.</summary>
    public int CallSiteInstructionRadius { get; }

    /// <summary>Gets the exact Task 9 function matches indexed by previous function RVA.</summary>
    public IReadOnlyDictionary<Rva, FunctionMatchResult> FunctionMatches { get; }

    /// <summary>Gets the direct signature results indexed by previous caller RVA.</summary>
    public IReadOnlyDictionary<Rva, SymbolAnalysis> SignedCallerAnchors { get; }

    /// <summary>Gets the previous image used for trusted-seed decoding and fingerprint normalization.</summary>
    public PeImage PreviousImage { get; }

    /// <summary>Gets the current image used for trusted-seed decoding and fingerprint normalization.</summary>
    public PeImage CurrentImage { get; }

    /// <summary>Gets the instruction decoder used for trusted-seed bounded decoding.</summary>
    public IInstructionDecoder Decoder { get; }
}

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

            var previousFingerprint = CallSiteFingerprint.Create(
                previousFunction,
                edge.CallSite,
                context.CallSiteInstructionRadius,
                checked((uint)context.PreviousImage.SizeOfImage));
            var matchingEdges = current.DirectCalls
                .Where(candidate => candidate.SourceFunction == currentCaller)
                .Where(candidate => candidate.Kind == edge.Kind)
                .Where(candidate => CallSiteFingerprint.Create(
                    currentFunction,
                    candidate.CallSite,
                    context.CallSiteInstructionRadius,
                    checked((uint)context.CurrentImage.SizeOfImage)).Sha256 == previousFingerprint.Sha256)
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

        var trustedSeed = TryRecoverTrustedSeed(directResult, previous, current, context, previousTarget);
        if (trustedSeed.Evidence is { } seedEvidence)
            evidence.Add(seedEvidence);
        hasNonAcceptingCallerMapping |= trustedSeed.HasNonAcceptingCallerMapping;
        hasUnsupportedCaller |= trustedSeed.HasUnsupportedCaller;
        hasUnmatchedCurrentCall |= trustedSeed.HasUnmatchedCurrentCall;
        hasCompetingCallSite |= trustedSeed.HasCompetingCallSite;

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

    private static FunctionGraph? FindContainingFunction(CallGraph graph, Rva rva) =>
        graph.Functions.FirstOrDefault(function =>
            function.Range.Begin.Value <= rva.Value && rva.Value < function.Range.End.Value);

    private static TrustedSeedResult TryRecoverTrustedSeed(
        SymbolAnalysis directResult,
        CallGraph previous,
        CallGraph current,
        CallerRecoveryContext context,
        Rva previousTarget) {
        if (directResult.PreviousScan.Truncated || directResult.PreviousScan.Matches.Length != 1 ||
            directResult.PreviousScan.Matches[0].ResolvedRva != previousTarget)
            return default;

        var previousCallSite = directResult.PreviousScan.Matches[0].PatternRva;
        var previousFunction = FindContainingFunction(previous, previousCallSite);
        if (previousFunction is null || previousFunction.IsSuspect ||
            previousFunction.Instructions.Any(instruction => instruction.Rva == previousCallSite))
            return default;

        if (!context.FunctionMatches.TryGetValue(previousFunction.Range.Begin, out var functionMatch))
            return default;
        if (functionMatch.Status != SymbolStatus.StructuralRecovered || functionMatch.CurrentTarget is not { } currentCaller) {
            return functionMatch.Status == SymbolStatus.Ambiguous || functionMatch.Candidates.Any(candidate => !candidate.Exact)
                ? new TrustedSeedResult(null, true, false, false, false)
                : default;
        }

        var currentFunction = FindFunction(current, currentCaller);
        if (currentFunction is null || currentFunction.IsSuspect)
            return new TrustedSeedResult(null, false, true, false, false);
        if (!TryDecodeWindow(context.PreviousImage, context.Decoder, previousFunction.Range, previousCallSite, out var previousWindow) ||
            !IsDirectOpcode(previousWindow[0]))
            return new TrustedSeedResult(null, false, true, false, false);

        var previousFingerprint = CallSiteFingerprint.Create(previousWindow, checked((uint)context.PreviousImage.SizeOfImage));
        var candidates = ImmutableArray.CreateBuilder<(Rva Candidate, ImmutableArray<DecodedInstruction> Window)>();
        foreach (var candidate in FindDirectOpcodeCandidates(context.CurrentImage, currentFunction.Range)) {
            if (!TryDecodeWindow(context.CurrentImage, context.Decoder, currentFunction.Range, candidate, out var window) ||
                !IsDirectOpcode(window[0]) ||
                CallSiteFingerprint.Create(window, checked((uint)context.CurrentImage.SizeOfImage)).Sha256 != previousFingerprint.Sha256)
                continue;

            candidates.Add((candidate, window));
        }

        var matchingCandidates = candidates
            .OrderBy(candidate => candidate.Candidate.Value)
            .ToImmutableArray();

        if (matchingCandidates.IsEmpty)
            return new TrustedSeedResult(null, false, false, true, false);
        if (matchingCandidates.Length != 1 || matchingCandidates[0].Window[0].NearBranchTarget is not { } currentTarget)
            return new TrustedSeedResult(null, false, false, false, true);

        return new TrustedSeedResult(
            new RecoveryEvidence(
                "TrustedCallSite",
                previousTarget,
                currentTarget,
                previousFunction.Range.Begin,
                previousCallSite,
                currentCaller,
                matchingCandidates[0].Candidate,
                previousFingerprint.Sha256),
            false,
            false,
            false,
            false);
    }

    private static ImmutableArray<Rva> FindDirectOpcodeCandidates(PeImage image, RuntimeFunctionRange range) {
        var length = checked((int)(range.End.Value - range.Begin.Value));
        if (!image.TryRead(range.Begin, length, out var bytes))
            return [];

        return bytes.Span
            .ToArray()
            .Select((value, index) => new { value, index })
            .Where(item => item.value is 0xE8 or 0xE9)
            .Select(item => new Rva(checked(range.Begin.Value + (uint)item.index)))
            .ToImmutableArray();
    }

    private static bool TryDecodeWindow(
        PeImage image,
        IInstructionDecoder decoder,
        RuntimeFunctionRange range,
        Rva start,
        out ImmutableArray<DecodedInstruction> instructions) {
        var decoded = ImmutableArray.CreateBuilder<DecodedInstruction>(CallSiteFingerprint.InstructionRadius + 1);
        var current = start;
        for (var index = 0; index <= CallSiteFingerprint.InstructionRadius; index++) {
            if (current.Value < range.Begin.Value || current.Value >= range.End.Value ||
                !image.TryRead(current, checked((int)(range.End.Value - current.Value)), out var bytes)) {
                instructions = [];
                return false;
            }

            var result = decoder.Decode(bytes.Span, current);
            if (!result.Success || result.Instruction is not { } instruction || instruction.Rva != current || instruction.Bytes.IsEmpty ||
                instruction.Bytes.Length > range.End.Value - current.Value) {
                instructions = [];
                return false;
            }

            decoded.Add(instruction);
            if (instruction.FlowControl is FlowControlKind.Return or FlowControlKind.Interrupt or FlowControlKind.Exception)
                break;
            current = new Rva(checked(current.Value + (uint)instruction.Bytes.Length));
        }

        instructions = decoded.ToImmutable();
        return !instructions.IsEmpty;
    }

    private static bool IsDirectOpcode(DecodedInstruction instruction) =>
        instruction.Bytes[0] is 0xE8 or 0xE9 &&
        instruction.FlowControl is FlowControlKind.DirectCall or FlowControlKind.DirectBranch &&
        instruction.NearBranchTarget is not null;

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

    private readonly record struct TrustedSeedResult(
        RecoveryEvidence? Evidence,
        bool HasNonAcceptingCallerMapping,
        bool HasUnsupportedCaller,
        bool HasUnmatchedCurrentCall,
        bool HasCompetingCallSite);
}
