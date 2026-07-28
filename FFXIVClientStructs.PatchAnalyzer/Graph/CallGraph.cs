using System.Collections.Immutable;
using FFXIVClientStructs.PatchAnalyzer.Binary;
using FFXIVClientStructs.PatchAnalyzer.Decoding;

namespace FFXIVClientStructs.PatchAnalyzer.Graph;

/// <summary>Defines the type of a direct control-flow edge.</summary>
public enum CallEdgeKind {
    /// <summary>Indicates a direct call instruction.</summary>
    DirectCall,
    /// <summary>Indicates an out-of-range direct unconditional branch.</summary>
    DirectTailJump
}

/// <summary>Describes a direct call or tail-jump discovered in a function.</summary>
public sealed record CallEdge(
    Rva SourceFunction,
    Rva CallSite,
    Rva Target,
    CallEdgeKind Kind);

/// <summary>Describes the instructions reachable from a runtime-function entry point.</summary>
public sealed record FunctionGraph(
    RuntimeFunctionRange Range,
    bool IsSuspect,
    ImmutableArray<DecodedInstruction> Instructions,
    ImmutableArray<string> Diagnostics) {
    /// <summary>Gets the sorted RVAs of the decoded reachable instructions.</summary>
    public ImmutableSortedSet<Rva> ReachableInstructions =>
        Instructions.Select(instruction => instruction.Rva)
            .ToImmutableSortedSet(Comparer<Rva>.Create(static (left, right) => left.Value.CompareTo(right.Value)));
}

/// <summary>Provides reachable function graphs and their direct control-flow edges.</summary>
public sealed class CallGraph {
    /// <summary>Initializes a new instance of the <see cref="CallGraph"/> class.</summary>
    public CallGraph(ImmutableArray<FunctionGraph> functions, ImmutableArray<CallEdge> directCalls) {
        Functions = functions;
        DirectCalls = directCalls;
    }

    /// <summary>Gets the graph for each indexed runtime function.</summary>
    public ImmutableArray<FunctionGraph> Functions { get; }

    /// <summary>Gets the sorted direct calls and tail jumps.</summary>
    public ImmutableArray<CallEdge> DirectCalls { get; }

    /// <summary>Finds direct edges targeting <paramref name="target"/>.</summary>
    /// <param name="target">The target RVA.</param>
    /// <returns>A sorted collection of incoming direct edges.</returns>
    public ImmutableArray<CallEdge> FindIncoming(Rva target) =>
        DirectCalls.Where(edge => edge.Target == target).ToImmutableArray();
}
