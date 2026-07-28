using System.Collections.Immutable;
using FFXIVClientStructs.PatchAnalyzer.Binary;
using FFXIVClientStructs.PatchAnalyzer.Decoding;

namespace FFXIVClientStructs.PatchAnalyzer.Graph;

/// <summary>Builds reachable instruction graphs for indexed runtime functions.</summary>
public static class CallGraphBuilder {
    /// <summary>Builds function graphs and direct control-flow edges from runtime-function entries.</summary>
    /// <param name="image">The PE image containing the function bytes.</param>
    /// <param name="functionIndex">The indexed runtime functions to traverse.</param>
    /// <param name="decoder">The instruction decoder to use.</param>
    /// <returns>A graph containing every indexed function and its direct edges.</returns>
    public static CallGraph Build(PeImage image, FunctionIndex functionIndex, IInstructionDecoder decoder) {
        var functions = ImmutableArray.CreateBuilder<FunctionGraph>(functionIndex.Ranges.Length);
        var edges = new List<CallEdge>();

        foreach (var range in functionIndex.Ranges)
            functions.Add(BuildFunction(image, range, decoder, edges));

        return new CallGraph(
            functions.OrderBy(function => function.Range.Begin.Value).ToImmutableArray(),
            edges.OrderBy(edge => edge.SourceFunction.Value)
                .ThenBy(edge => edge.CallSite.Value)
                .ThenBy(edge => edge.Target.Value)
                .ThenBy(edge => edge.Kind)
                .ToImmutableArray());
    }

    private static FunctionGraph BuildFunction(PeImage image, RuntimeFunctionRange range, IInstructionDecoder decoder, List<CallEdge> edges) {
        var pending = new Queue<Rva>();
        var decoded = new Dictionary<Rva, DecodedInstruction>();
        var diagnostics = new List<string>();
        var isSuspect = false;
        pending.Enqueue(range.Begin);

        while (pending.TryDequeue(out var rva)) {
            if (!IsInRange(range, rva) || decoded.ContainsKey(rva))
                continue;

            var remainingLength = checked((int)(range.End.Value - rva.Value));
            if (!image.TryRead(rva, remainingLength, out var bytes)) {
                isSuspect = true;
                diagnostics.Add($"Could not read function bytes at RVA 0x{rva.Value:X8}.");
                continue;
            }

            var result = decoder.Decode(bytes.Span, rva);
            if (!result.Success || result.Instruction is null) {
                isSuspect = true;
                diagnostics.Add($"Could not decode instruction at RVA 0x{rva.Value:X8}: {result.Error ?? "Unknown decoder failure."}");
                continue;
            }

            var instruction = result.Instruction;
            if (instruction.Rva != rva || instruction.Bytes.Length == 0 || instruction.Bytes.Length > remainingLength) {
                isSuspect = true;
                diagnostics.Add($"Decoder returned an invalid instruction extent at RVA 0x{rva.Value:X8}.");
                continue;
            }

            decoded.Add(rva, instruction);
            var fallthrough = new Rva(checked(rva.Value + (uint)instruction.Bytes.Length));
            switch (instruction.FlowControl) {
                case FlowControlKind.DirectCall:
                    if (instruction.NearBranchTarget is { } callTarget)
                        edges.Add(new CallEdge(range.Begin, rva, callTarget, CallEdgeKind.DirectCall));
                    EnqueueFallthrough(range, pending, fallthrough);
                    break;
                case FlowControlKind.ConditionalBranch:
                    EnqueueIfInRange(range, pending, instruction.NearBranchTarget);
                    EnqueueFallthrough(range, pending, fallthrough);
                    break;
                case FlowControlKind.Transactional:
                    EnqueueIfInRange(range, pending, instruction.NearBranchTarget);
                    EnqueueFallthrough(range, pending, fallthrough);
                    break;
                case FlowControlKind.DirectBranch:
                    if (instruction.NearBranchTarget is { } branchTarget) {
                        if (IsInRange(range, branchTarget))
                            pending.Enqueue(branchTarget);
                        else
                            edges.Add(new CallEdge(range.Begin, rva, branchTarget, CallEdgeKind.DirectTailJump));
                    }
                    break;
                case FlowControlKind.Return:
                case FlowControlKind.Exception:
                case FlowControlKind.Interrupt:
                case FlowControlKind.IndirectBranch:
                    break;
                default:
                    EnqueueFallthrough(range, pending, fallthrough);
                    break;
            }
        }

        return new FunctionGraph(
            range,
            isSuspect,
            decoded.Values.OrderBy(instruction => instruction.Rva.Value).ToImmutableArray(),
            diagnostics.OrderBy(diagnostic => diagnostic, StringComparer.Ordinal).ToImmutableArray());
    }

    private static void EnqueueFallthrough(RuntimeFunctionRange range, Queue<Rva> pending, Rva fallthrough) {
        if (IsInRange(range, fallthrough))
            pending.Enqueue(fallthrough);
    }

    private static void EnqueueIfInRange(RuntimeFunctionRange range, Queue<Rva> pending, Rva? target) {
        if (target is { } value && IsInRange(range, value))
            pending.Enqueue(value);
    }

    private static bool IsInRange(RuntimeFunctionRange range, Rva rva) =>
        rva.Value >= range.Begin.Value && rva.Value < range.End.Value;
}
