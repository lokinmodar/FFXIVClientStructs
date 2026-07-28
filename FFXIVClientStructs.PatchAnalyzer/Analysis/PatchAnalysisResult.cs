using System.Collections.Immutable;
using FFXIVClientStructs.PatchAnalyzer.Binary;
using FFXIVClientStructs.PatchAnalyzer.Data;

namespace FFXIVClientStructs.PatchAnalyzer.Analysis;

/// <summary>Contains the deterministic inputs used to render patch-analysis artifacts.</summary>
public sealed record PatchAnalysisResult(
    string RunStatus,
    string ToolVersion,
    string RepositoryVersion,
    BinaryIdentity PreviousBinary,
    BinaryIdentity CurrentBinary,
    ulong CurrentImageBase,
    AnalysisConfiguration Configuration,
    DataCatalog Data,
    ImmutableArray<SymbolAnalysis> Symbols,
    AnalysisMetrics Metrics,
    ImmutableSortedDictionary<string, long> WorkloadCounts);
