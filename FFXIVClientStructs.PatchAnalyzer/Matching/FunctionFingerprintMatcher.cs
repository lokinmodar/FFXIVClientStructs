using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;
using FFXIVClientStructs.PatchAnalyzer.Analysis;
using FFXIVClientStructs.PatchAnalyzer.Binary;
using FFXIVClientStructs.PatchAnalyzer.Decoding;
using FFXIVClientStructs.PatchAnalyzer.Graph;

namespace FFXIVClientStructs.PatchAnalyzer.Matching;

/// <summary>Describes a normalized, whole-function identity.</summary>
public sealed record FunctionFingerprint(
    string Sha256,
    ImmutableArray<string> BasicBlockKeys,
    int InstructionCount,
    int DirectEdgeCount);

/// <summary>Describes a deterministically ranked structural-match diagnostic.</summary>
public sealed record FunctionMatchCandidate(
    Rva CurrentTarget,
    bool Exact,
    int Rank,
    string FingerprintSha256);

/// <summary>Describes the result of matching one previous function against current functions.</summary>
public sealed record FunctionMatchResult(
    SymbolStatus Status,
    Rva? CurrentTarget,
    FunctionFingerprint PreviousFingerprint,
    ImmutableArray<FunctionMatchCandidate> Candidates);

/// <summary>Creates normalized whole-function fingerprints and deterministic match diagnostics.</summary>
public static class FunctionFingerprintMatcher {
    /// <summary>Creates a normalized fingerprint for <paramref name="function"/>.</summary>
    /// <param name="function">The reachable function graph to normalize.</param>
    /// <returns>A deterministic whole-function fingerprint.</returns>
    public static FunctionFingerprint Create(FunctionGraph function) {
        ArgumentNullException.ThrowIfNull(function);

        var instructions = function.Instructions.OrderBy(instruction => instruction.Rva.Value).ToImmutableArray();
        var blocks = BuildBlocks(instructions);
        var traversal = TraverseBlocks(blocks);
        var keys = traversal.Select(block => BlockKey(block, traversal, function.Range)).ToImmutableArray();
        var canonical = string.Join("\n", keys);
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
        var directEdgeCount = instructions.Count(instruction => IsDirectEdge(instruction, function.Range));

        return new FunctionFingerprint(hash, keys, instructions.Length, directEdgeCount);
    }

    /// <summary>Matches <paramref name="previous"/> against every function in <paramref name="current"/>.</summary>
    /// <param name="previous">The accepted previous function graph.</param>
    /// <param name="current">The current call graph whose functions are candidates.</param>
    /// <returns>An exact structural recovery or a deterministic non-acceptance result.</returns>
    public static FunctionMatchResult Match(FunctionGraph previous, CallGraph current) {
        ArgumentNullException.ThrowIfNull(previous);
        ArgumentNullException.ThrowIfNull(current);

        var previousFingerprint = Create(previous);
        var candidates = current.Functions
            .OrderBy(function => function.Range.Begin.Value)
            .Select(function => new Candidate(function.Range.Begin, Create(function)))
            .ToImmutableArray();
        var exactTargets = candidates.Where(candidate => candidate.Fingerprint.Sha256 == previousFingerprint.Sha256).ToImmutableArray();

        if (exactTargets.Length == 1) {
            var match = exactTargets[0];
            return new FunctionMatchResult(
                SymbolStatus.StructuralRecovered,
                match.Target,
                previousFingerprint,
                [new FunctionMatchCandidate(match.Target, true, 1, match.Fingerprint.Sha256)]);
        }

        if (exactTargets.Length > 1) {
            var diagnostics = exactTargets
                .OrderBy(candidate => candidate.Target.Value)
                .Select((candidate, index) => new FunctionMatchCandidate(candidate.Target, true, index + 1, candidate.Fingerprint.Sha256))
                .ToImmutableArray();
            return new FunctionMatchResult(SymbolStatus.Ambiguous, null, previousFingerprint, diagnostics);
        }

        var ranked = candidates
            .Select(candidate => new { Candidate = candidate, Score = SimilarityScore(previousFingerprint, candidate.Fingerprint) })
            .Where(entry => entry.Score > 0)
            .OrderByDescending(entry => entry.Score)
            .ThenBy(entry => entry.Candidate.Target.Value)
            .Select((entry, index) => new FunctionMatchCandidate(
                entry.Candidate.Target,
                false,
                index + 1,
                entry.Candidate.Fingerprint.Sha256))
            .ToImmutableArray();

        return new FunctionMatchResult(
            ranked.IsEmpty ? SymbolStatus.Missing : SymbolStatus.Ambiguous,
            null,
            previousFingerprint,
            ranked);
    }

    private static ImmutableArray<BasicBlock> BuildBlocks(ImmutableArray<DecodedInstruction> instructions) {
        if (instructions.IsEmpty)
            return [];

        var indexByRva = instructions
            .Select((instruction, index) => new { instruction.Rva, index })
            .ToDictionary(entry => entry.Rva, entry => entry.index);
        var starts = new SortedSet<int> { 0 };
        for (var index = 0; index < instructions.Length; index++) {
            var instruction = instructions[index];
            if (instruction.NearBranchTarget is { } target && indexByRva.TryGetValue(target, out var targetIndex))
                starts.Add(targetIndex);
            if (EndsBasicBlock(instruction) && index + 1 < instructions.Length)
                starts.Add(index + 1);
        }

        var blockStarts = starts.ToArray();
        var blockByInstruction = new int[instructions.Length];
        var blocks = new BasicBlock[blockStarts.Length];
        for (var blockIndex = 0; blockIndex < blockStarts.Length; blockIndex++) {
            var start = blockStarts[blockIndex];
            var end = blockIndex + 1 < blockStarts.Length ? blockStarts[blockIndex + 1] : instructions.Length;
            for (var instructionIndex = start; instructionIndex < end; instructionIndex++)
                blockByInstruction[instructionIndex] = blockIndex;
            blocks[blockIndex] = new BasicBlock(blockIndex, instructions[start..end], []);
        }

        for (var blockIndex = 0; blockIndex < blocks.Length; blockIndex++) {
            var last = blocks[blockIndex].Instructions[^1];
            var successors = ImmutableArray.CreateBuilder<BlockSuccessor>();
            if (last.NearBranchTarget is { } target && indexByRva.TryGetValue(target, out var targetIndex))
                successors.Add(new BlockSuccessor("target", blockByInstruction[targetIndex]));
            if (HasFallThrough(last) && blockIndex + 1 < blocks.Length)
                successors.Add(new BlockSuccessor("next", blockIndex + 1));
            blocks[blockIndex] = blocks[blockIndex] with { Successors = [.. successors] };
        }

        return [.. blocks];
    }

    private static ImmutableArray<BasicBlock> TraverseBlocks(ImmutableArray<BasicBlock> blocks) {
        if (blocks.IsEmpty)
            return [];

        var visited = new bool[blocks.Length];
        var pending = new Queue<int>();
        var ordered = ImmutableArray.CreateBuilder<BasicBlock>(blocks.Length);
        pending.Enqueue(0);
        while (pending.Count > 0) {
            var index = pending.Dequeue();
            if (visited[index])
                continue;

            visited[index] = true;
            var block = blocks[index];
            ordered.Add(block);
            foreach (var successor in block.Successors)
                pending.Enqueue(successor.BlockIndex);
        }

        return [.. ordered];
    }

    private static string BlockKey(BasicBlock block, ImmutableArray<BasicBlock> traversal, RuntimeFunctionRange range) {
        var blockOrder = traversal
            .Select((item, index) => new { item.Index, index })
            .ToDictionary(entry => entry.Index, entry => entry.index);
        var instructions = string.Join(",", block.Instructions.Select(instruction => InstructionKey(instruction, range)));
        var successors = string.Join(",", block.Successors.Select(successor => $"{successor.Kind}:B{blockOrder[successor.BlockIndex]}"));
        return $"{instructions}|{successors}";
    }

    private static string InstructionKey(DecodedInstruction instruction, RuntimeFunctionRange range) {
        var constants = string.Join(",", instruction.Constants.Select(ConstantKey));
        var directEdgeKind = instruction.FlowControl switch {
            FlowControlKind.DirectCall => "|edge:call",
            FlowControlKind.DirectBranch when IsOutsideRange(instruction.NearBranchTarget, range) => "|edge:tail-jump",
            _ => string.Empty
        };
        var ipReference = instruction.IpRelativeTarget is null ? string.Empty : "|ip-reference";
        return $"{instruction.OpcodeKey}|{instruction.FlowControl}|{constants}{ipReference}{directEdgeKind}";
    }

    private static string ConstantKey(DecodedConstant constant) => constant.Kind switch {
        EncodedConstantKind.BranchDisplacement => "branch",
        EncodedConstantKind.IpRelativeDisplacement => "ip-relative",
        _ => $"{constant.Kind}:{constant.UnsignedValue:X}"
    };

    private static bool EndsBasicBlock(DecodedInstruction instruction) => instruction.FlowControl is
        FlowControlKind.ConditionalBranch or
        FlowControlKind.DirectBranch or
        FlowControlKind.IndirectBranch or
        FlowControlKind.Return or
        FlowControlKind.Interrupt or
        FlowControlKind.Exception or
        FlowControlKind.Transactional;

    private static bool HasFallThrough(DecodedInstruction instruction) => instruction.FlowControl is
        FlowControlKind.Next or
        FlowControlKind.DirectCall or
        FlowControlKind.IndirectCall or
        FlowControlKind.ConditionalBranch or
        FlowControlKind.Transactional;

    private static bool IsDirectEdge(DecodedInstruction instruction, RuntimeFunctionRange range) =>
        instruction.FlowControl == FlowControlKind.DirectCall ||
        instruction.FlowControl == FlowControlKind.DirectBranch && IsOutsideRange(instruction.NearBranchTarget, range);

    private static bool IsOutsideRange(Rva? target, RuntimeFunctionRange range) =>
        target is { } rva && (rva.Value < range.Begin.Value || rva.Value >= range.End.Value);

    private static int SimilarityScore(FunctionFingerprint previous, FunctionFingerprint current) {
        var previousKeys = previous.BasicBlockKeys.ToHashSet(StringComparer.Ordinal);
        var commonBlocks = current.BasicBlockKeys.Count(previousKeys.Contains);
        var instructionDelta = Math.Abs(previous.InstructionCount - current.InstructionCount);
        var edgeDelta = Math.Abs(previous.DirectEdgeCount - current.DirectEdgeCount);
        return commonBlocks * 100 - instructionDelta * 10 - edgeDelta;
    }

    private sealed record Candidate(Rva Target, FunctionFingerprint Fingerprint);

    private sealed record BasicBlock(int Index, ImmutableArray<DecodedInstruction> Instructions, ImmutableArray<BlockSuccessor> Successors);

    private sealed record BlockSuccessor(string Kind, int BlockIndex);
}
