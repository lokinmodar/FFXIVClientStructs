using System.Collections.Immutable;

namespace FFXIVClientStructs.PatchAnalyzer.Analysis;

/// <summary>Records elapsed stage timings for console progress reporting.</summary>
public sealed record AnalysisMetrics(ImmutableSortedDictionary<string, long> StageMilliseconds);
