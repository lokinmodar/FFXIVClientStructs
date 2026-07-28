using System.Collections.Immutable;
using System.Reflection;
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
    public void CandidateYaml_NormalizesCrLfAndAddsOneFinalNewline() {
        const string source = "version: old\r\nglobals: {}\r\nfunctions: {}\r\nclasses: {}";

        var output = CandidateYamlWriter.Render(TestResults.WithVersionOverride(source, "new"));

        Assert.DoesNotContain('\r', output);
        Assert.EndsWith("classes: {}\n", output, StringComparison.Ordinal);
        Assert.False(output.EndsWith("\n\n", StringComparison.Ordinal));
    }

    [Fact]
    public void Write_ChangedInputSource_RejectsStaleCatalogAndDoesNotWriteCandidate() {
        const string source = """
                              version: old
                              globals: {}
                              functions:
                                0x140001000: Test
                              classes: {}
                              """;
        var result = TestResults.OneAcceptedReplacement(source, "0x140001000", "0x140003000");
        var directory = Path.Combine(Path.GetTempPath(), $"PatchAnalyzerTests-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        var inputPath = Path.Combine(directory, "data.yml");
        var outputPath = Path.Combine(directory, "data.candidate.yml");
        File.WriteAllText(inputPath, source.Replace("0x140001000", "0x140001001", StringComparison.Ordinal), new UTF8Encoding(false));

        try {
            Assert.Throws<InvalidOperationException>(() => CandidateYamlWriter.Write(result, inputPath, outputPath, TestContext.Current.CancellationToken));

            Assert.False(File.Exists(outputPath));
        } finally {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void CandidateYaml_DuplicateReplacementSpans_Throws() {
        const string source = """
                              version: old
                              globals: {}
                              functions:
                                0x140001000: Test
                              classes: {}
                              """;
        var result = TestResults.WithAnalyses(source, [
            TestResults.Analysis(SymbolStatus.DirectUnique, 0x1000, 0x3000),
            TestResults.Analysis(SymbolStatus.StructuralRecovered, 0x1000, 0x4000)
        ]);

        var exception = Assert.Throws<InvalidOperationException>(() => CandidateYamlWriter.Render(result));

        Assert.Contains("unique", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void CandidateYaml_OverlappingReplacementSpans_Throws() {
        const string source = "version: old\nglobals: {}\nfunctions: {}\nclasses: {}\n";
        var catalog = TestResults.CatalogWithLocations(source, [
            new DataLocation("First", LocationKind.Function, new PreferredVa(0x140001000), new Rva(0x1000), new SourceSpan(0, 8)),
            new DataLocation("Second", LocationKind.Function, new PreferredVa(0x140001001), new Rva(0x1001), new SourceSpan(4, 8))
        ]);
        var result = TestResults.WithCatalog(catalog, [
            TestResults.Analysis(SymbolStatus.DirectUnique, 0x1000, 0x3000),
            TestResults.Analysis(SymbolStatus.CallerRecovered, 0x1001, 0x4000)
        ]);

        var exception = Assert.Throws<InvalidOperationException>(() => CandidateYamlWriter.Render(result));

        Assert.Contains("overlap", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Write_EqualInputAndOutputPaths_Throws() {
        var path = Path.Combine(Path.GetTempPath(), $"PatchAnalyzerTests-{Guid.NewGuid():N}.yml");

        try {
            Assert.Throws<ArgumentException>(() => CandidateYamlWriter.Write(TestResults.WithMetrics(), path, path, TestContext.Current.CancellationToken));
        } finally {
            if (File.Exists(path))
                File.Delete(path);
        }
    }

    [Fact]
    public void Write_FailedRun_DoesNotWriteCandidate() {
        var directory = Path.Combine(Path.GetTempPath(), $"PatchAnalyzerTests-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        var inputPath = Path.Combine(directory, "data.yml");
        var outputPath = Path.Combine(directory, "data.candidate.yml");
        var result = TestResults.WithMetrics() with { RunStatus = "failed" };
        File.WriteAllText(inputPath, result.Data.SourceText, new UTF8Encoding(false));

        try {
            Assert.Throws<InvalidOperationException>(() => CandidateYamlWriter.Write(result, inputPath, outputPath, TestContext.Current.CancellationToken));

            Assert.False(File.Exists(outputPath));
        } finally {
            Directory.Delete(directory, recursive: true);
        }
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

        public static PatchAnalysisResult WithAnalyses(string source, SymbolAnalysis[] analyses) => Create(source, analyses);

        public static PatchAnalysisResult WithCatalog(DataCatalog catalog, SymbolAnalysis[] analyses) => new(
            "succeeded",
            Identity("previous.exe", "old"),
            new BinaryIdentity("current.exe", 123, new string('A', 64), null, "none"),
            new AnalysisConfiguration(10, 96, 8, null, null),
            catalog,
            analyses.ToImmutableArray(),
            new AnalysisMetrics(ImmutableSortedDictionary<string, long>.Empty),
            ImmutableSortedDictionary<string, long>.Empty);

        public static DataCatalog CatalogWithLocations(string source, DataLocation[] locations) {
            var constructor = typeof(DataCatalog).GetConstructor(BindingFlags.Instance | BindingFlags.NonPublic, null, [typeof(string), typeof(string), typeof(SourceSpan), typeof(ImmutableArray<DataLocation>), typeof(ImmutableHashSet<string>)], null)!;
            return (DataCatalog)constructor.Invoke([source, "old", new SourceSpan(0, 3), locations.ToImmutableArray(), ImmutableHashSet<string>.Empty]);
        }

        private static PatchAnalysisResult Create(string source, SymbolAnalysis[] analyses, params (string Stage, long Milliseconds)[] metrics) => new(
            "succeeded",
            Identity("previous.exe", "old"),
            Identity("current.exe", "new"),
            new AnalysisConfiguration(10, 96, 8, null, null),
            DataCatalog.Parse(source, ImageBase),
            analyses.ToImmutableArray(),
            new AnalysisMetrics(metrics.ToImmutableSortedDictionary(metric => metric.Stage, metric => metric.Milliseconds, StringComparer.Ordinal)),
            ImmutableSortedDictionary.CreateRange(StringComparer.Ordinal, new Dictionary<string, long> { ["signatures"] = analyses.Length }));

        public static SymbolAnalysis Analysis(SymbolStatus status, uint previousRva, uint currentRva) => new(
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
