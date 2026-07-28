using System.Collections.Immutable;
using System.Text;
using FFXIVClientStructs.PatchAnalyzer.Analysis;
using FFXIVClientStructs.PatchAnalyzer.Binary;
using FFXIVClientStructs.PatchAnalyzer.Data;
using FFXIVClientStructs.PatchAnalyzer.Output;
using FFXIVClientStructs.PatchAnalyzer.Signatures;
using Xunit;

namespace FFXIVClientStructs.PatchAnalyzer.Tests.Output;

public class ArtifactWriterTests {
    [Fact]
    public void Write_SameResultTwice_ProducesByteIdenticalArtifacts() {
        var firstResult = TestResults.WithMetrics(("load", 12L), ("scan", 34L));
        var secondResult = TestResults.WithMetrics(("load", 91L), ("scan", 7L));

        var first = ArtifactWriters.WriteToBytes(firstResult);
        var second = ArtifactWriters.WriteToBytes(secondResult);

        Assert.Equal(first.Report, second.Report);
        Assert.Equal(first.CandidateYaml, second.CandidateYaml);
    }

    [Fact]
    public void CandidateYaml_ReplacesOnlyAcceptedSpansAndPreservesText() {
        const string source = """
                              version: old # keep
                              globals: {}
                              functions: {}
                              classes:
                                A:
                                  funcs:
                                    0x140001000: One # accepted
                                    0x140002000: Two # unresolved
                              """;
        var result = TestResults.OneAcceptedReplacement(source, "0x140001000", "0x140003000");

        var output = CandidateYamlWriter.Render(result);

        Assert.Contains("0x140003000: One # accepted", output, StringComparison.Ordinal);
        Assert.Contains("0x140002000: Two # unresolved", output, StringComparison.Ordinal);
        Assert.DoesNotContain("0x140001000: One", output, StringComparison.Ordinal);
    }

    [Fact]
    public void CandidateYaml_ReplacementForNonAcceptedStatus_Throws() {
        var result = TestResults.OneReplacement(SymbolStatus.Ambiguous);

        var exception = Assert.Throws<InvalidOperationException>(() => CandidateYamlWriter.Render(result));

        Assert.Contains("non-accepted", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void CandidateYaml_ExplicitCurrentVersion_ReplacesOnlyVersionToken() {
        const string source = """
                              version: old # keep
                              globals: {}
                              functions: {}
                              classes: {}
                              """;
        var result = TestResults.WithVersionOverride(source, "2026.07.28.0000.0000");

        var output = CandidateYamlWriter.Render(result);

        Assert.StartsWith("# REVIEW REQUIRED: generated candidate; verify before applying.\nversion: 2026.07.28.0000.0000 # keep\n", output, StringComparison.Ordinal);
    }

    [Fact]
    public void Write_CancellationDuringWrite_LeavesNoTemporaryFile() {
        var directory = Path.Combine(Path.GetTempPath(), $"PatchAnalyzerTests-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        var destination = Path.Combine(directory, "report.json");
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        try {
            Assert.Throws<OperationCanceledException>(() => AtomicFileWriter.Write(destination, stream => {
                stream.WriteByte(1);
                cancellation.Token.ThrowIfCancellationRequested();
            }, cancellation.Token));

            Assert.Empty(Directory.EnumerateFiles(directory));
        } finally {
            Directory.Delete(directory, recursive: true);
        }
    }

    private static class ArtifactWriters {
        public static ArtifactBytes WriteToBytes(PatchAnalysisResult result) {
            using var report = new MemoryStream();
            using var candidateYaml = new MemoryStream();
            ReportWriter.Render(result, report);
            CandidateYamlWriter.Render(result, candidateYaml);
            return new ArtifactBytes(report.ToArray(), candidateYaml.ToArray());
        }
    }

    private sealed record ArtifactBytes(byte[] Report, byte[] CandidateYaml);

    private static class TestResults {
        private const ulong ImageBase = 0x140000000;

        public static PatchAnalysisResult WithMetrics(params (string Stage, long Milliseconds)[] metrics) => Create(
            """
            version: old
            globals: {}
            functions:
              0x140001000: Test
            classes: {}
            """,
            [Analysis(SymbolStatus.DirectUnique, 0x1000, 0x3000)],
            metrics);

        public static PatchAnalysisResult OneAcceptedReplacement(string source, string oldAddress, string newAddress) => Create(
            source,
            [Analysis(SymbolStatus.DirectUnique, ParseRva(oldAddress), ParseRva(newAddress))]);

        public static PatchAnalysisResult OneReplacement(SymbolStatus status) => Create(
            """
            version: old
            globals: {}
            functions:
              0x140001000: Test
            classes: {}
            """,
            [Analysis(status, 0x1000, 0x3000)]);

        public static PatchAnalysisResult WithVersionOverride(string source, string version) => new(
            "succeeded",
            Identity("previous.exe", "old"),
            Identity("current.exe", "new"),
            new AnalysisConfiguration(10, 96, 8, null, version),
            DataCatalog.Parse(source, ImageBase),
            ImmutableArray<SymbolAnalysis>.Empty,
            new AnalysisMetrics(ImmutableSortedDictionary<string, long>.Empty),
            ImmutableSortedDictionary<string, long>.Empty);

        private static PatchAnalysisResult Create(string source, SymbolAnalysis[] analyses, params (string Stage, long Milliseconds)[] metrics) => new(
            "succeeded",
            Identity("previous.exe", "old"),
            Identity("current.exe", "new"),
            new AnalysisConfiguration(10, 96, 8, null, null),
            DataCatalog.Parse(source, ImageBase),
            analyses.ToImmutableArray(),
            new AnalysisMetrics(metrics.ToImmutableSortedDictionary(metric => metric.Stage, metric => metric.Milliseconds, StringComparer.Ordinal)),
            ImmutableSortedDictionary.CreateRange(StringComparer.Ordinal, new Dictionary<string, long> { ["signatures"] = analyses.Length }));

        private static SymbolAnalysis Analysis(SymbolStatus status, uint previousRva, uint currentRva) => new(
            "Test.Symbol",
            "Test::Symbol",
            LocationKind.Function,
            SignatureDefinition.Parse("Test.Symbol", "40 53", []),
            new Rva(previousRva),
            new SignatureScanResult([], false, []),
            new SignatureScanResult([], false, []),
            status,
            new Rva(currentRva),
            ImmutableArray<RecoveryEvidence>.Empty,
            null,
            ImmutableArray<string>.Empty);

        private static BinaryIdentity Identity(string fileName, string version) => new(fileName, 123, new string('A', 64), version, "ffxivgame.ver");

        private static uint ParseRva(string address) => checked((uint)(Convert.ToUInt64(address[2..], 16) - ImageBase));
    }
}
