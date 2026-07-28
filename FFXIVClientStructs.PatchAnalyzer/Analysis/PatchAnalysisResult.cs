using System.Collections.Immutable;
using FFXIVClientStructs.PatchAnalyzer.Binary;
using FFXIVClientStructs.PatchAnalyzer.Data;

namespace FFXIVClientStructs.PatchAnalyzer.Analysis;

/// <summary>Contains the deterministic inputs used to render patch-analysis artifacts.</summary>
public sealed record PatchAnalysisResult(
    string RunStatus,
    BinaryIdentity PreviousBinary,
    BinaryIdentity CurrentBinary,
    AnalysisConfiguration Configuration,
    DataCatalog Data,
    ImmutableArray<SymbolAnalysis> Symbols,
    AnalysisMetrics Metrics,
    ImmutableSortedDictionary<string, long> WorkloadCounts);
