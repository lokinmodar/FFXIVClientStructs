using System.Collections.Immutable;
using System.Text;
using FFXIVClientStructs.PatchAnalyzer.Analysis;
using FFXIVClientStructs.PatchAnalyzer.Cli;
using FFXIVClientStructs.PatchAnalyzer.Decoding;
using FFXIVClientStructs.PatchAnalyzer.Signatures;
using FFXIVClientStructs.PatchAnalyzer.Tests.Fixtures;
using Xunit;

namespace FFXIVClientStructs.PatchAnalyzer.Tests.Integration;

public class PatchAnalyzerApplicationTests {
    [Fact]
    public async Task RunAsync_IdenticalExecutables_ReturnsInvalidInputWithoutArtifacts() {
        using var fixture = TestPatchPair.SameExecutable();

        var exitCode = await fixture.Application.RunAsync(fixture.Options, CancellationToken.None);

        Assert.Equal(ExitCode.InvalidInput, exitCode);
        Assert.False(File.Exists(Path.Combine(fixture.OutputDirectory, "report.json")));
    }

    [Fact]
    public async Task RunAsync_DirectUnique_WritesReportAndCandidateYaml() {
        using var fixture = TestPatchPair.DirectUnique();

        var exitCode = await fixture.Application.RunAsync(fixture.Options, CancellationToken.None);

        Assert.Equal(ExitCode.Success, exitCode);
        Assert.Contains("\"direct_unique\"", File.ReadAllText(fixture.ReportPath), StringComparison.Ordinal);
        Assert.True(File.Exists(fixture.CandidateYamlPath));
    }

    private sealed class TestPatchPair : IDisposable {
        private const ulong ImageBase = 0x140000000;
        private readonly string root;

        private TestPatchPair(string root, string previousExecutable, string currentExecutable, string dataFile, string outputDirectory) {
            this.root = root;
            OutputDirectory = outputDirectory;
            Options = new AnalyzerOptions(previousExecutable, currentExecutable, dataFile, outputDirectory, null, null);
            Application = new PatchAnalyzerApplication(new TestSignatureInventory(), new IcedInstructionDecoder());
        }

        public PatchAnalyzerApplication Application { get; }
        public AnalyzerOptions Options { get; }
        public string OutputDirectory { get; }
        public string ReportPath => Path.Combine(OutputDirectory, "report.json");
        public string CandidateYamlPath => Path.Combine(OutputDirectory, "data.candidate.yml");

        public static TestPatchPair SameExecutable() => Create([0x40, 0x53, 0xC3], [0x40, 0x53, 0xC3]);

        public static TestPatchPair DirectUnique() => Create([0x40, 0x53, 0xC3], [0x40, 0x53, 0x90, 0xC3]);

        public void Dispose() {
            if (Directory.Exists(root))
                Directory.Delete(root, recursive: true);
        }

        private static TestPatchPair Create(byte[] previousText, byte[] currentText) {
            var root = Path.Combine(Path.GetTempPath(), $"FFXIVClientStructs.PatchAnalyzer.Tests.{Guid.NewGuid():N}");
            Directory.CreateDirectory(root);
            var previousExecutable = Path.Combine(root, "previous.exe");
            var currentExecutable = Path.Combine(root, "current.exe");
            var dataFile = Path.Combine(root, "data.yml");
            var outputDirectory = Path.Combine(root, "output");

            using var previousFixture = SyntheticPeBuilder.Create()
                .WithSection(".text", 0x1000, previousText, executable: true)
                .Write();
            using var currentFixture = SyntheticPeBuilder.Create()
                .WithSection(".text", 0x1000, currentText, executable: true)
                .Write();
            File.Copy(previousFixture.ExecutablePath, previousExecutable);
            File.Copy(currentFixture.ExecutablePath, currentExecutable);
            File.WriteAllText(dataFile, $$"""
                version: old
                globals: {}
                functions:
                  0x{{ImageBase + 0x1000:X}}: Test::Symbol
                classes: {}
                """, new UTF8Encoding(false));

            return new TestPatchPair(root, previousExecutable, currentExecutable, dataFile, outputDirectory);
        }

        private sealed class TestSignatureInventory : ISignatureInventory {
            public ImmutableArray<SignatureDefinition> Load() =>
                [SignatureDefinition.Parse("FFXIVClientStructs.FFXIV.Test.Symbol", "40 53", [])];
        }
    }
}
