using System.Collections.Immutable;
using System.Text;
using FFXIVClientStructs.PatchAnalyzer.Analysis;
using FFXIVClientStructs.PatchAnalyzer.Binary;
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

    [Fact]
    public async Task RunAsync_DecoderPreflightFails_ReturnsInvalidInputWithoutOutputDirectory() {
        using var fixture = TestPatchPair.DirectUnique(new ThrowingInstructionDecoder());

        var exitCode = await fixture.Application.RunAsync(fixture.Options, CancellationToken.None);

        Assert.Equal(ExitCode.InvalidInput, exitCode);
        Assert.False(Directory.Exists(fixture.OutputDirectory));
    }

    [Fact]
    public async Task RunAsync_DecoderFailsAfterPreflight_WritesFailedReportWithoutCandidateYaml() {
        using var fixture = TestPatchPair.WithRuntimeFunctions(new GraphFailingInstructionDecoder());

        var exitCode = await fixture.Application.RunAsync(fixture.Options, CancellationToken.None);

        Assert.Equal(ExitCode.FatalAnalysis, exitCode);
        Assert.Contains("\"failed\"", File.ReadAllText(fixture.ReportPath), StringComparison.Ordinal);
        Assert.False(File.Exists(fixture.CandidateYamlPath));
    }

    private sealed class TestPatchPair : IDisposable {
        private const ulong ImageBase = 0x140000000;
        private readonly string root;

        private TestPatchPair(string root, string previousExecutable, string currentExecutable, string dataFile, string outputDirectory, IInstructionDecoder instructionDecoder) {
            this.root = root;
            OutputDirectory = outputDirectory;
            Options = new AnalyzerOptions(previousExecutable, currentExecutable, dataFile, outputDirectory, null, null);
            Application = new PatchAnalyzerApplication(new TestSignatureInventory(), instructionDecoder);
        }

        public PatchAnalyzerApplication Application { get; }
        public AnalyzerOptions Options { get; }
        public string OutputDirectory { get; }
        public string ReportPath => Path.Combine(OutputDirectory, "report.json");
        public string CandidateYamlPath => Path.Combine(OutputDirectory, "data.candidate.yml");

        public static TestPatchPair SameExecutable() => Create([0x40, 0x53, 0xC3], [0x40, 0x53, 0xC3]);

        public static TestPatchPair DirectUnique(IInstructionDecoder? instructionDecoder = null) =>
            Create([0x40, 0x53, 0xC3], [0x40, 0x53, 0x90, 0xC3], instructionDecoder: instructionDecoder);

        public static TestPatchPair WithRuntimeFunctions(IInstructionDecoder instructionDecoder) =>
            Create([0x40, 0x53, 0xC3], [0x40, 0x53, 0x90, 0xC3], instructionDecoder, withRuntimeFunctions: true);

        public void Dispose() {
            if (Directory.Exists(root))
                Directory.Delete(root, recursive: true);
        }

        private static TestPatchPair Create(byte[] previousText, byte[] currentText, IInstructionDecoder? instructionDecoder = null, bool withRuntimeFunctions = false) {
            var root = Path.Combine(Path.GetTempPath(), $"FFXIVClientStructs.PatchAnalyzer.Tests.{Guid.NewGuid():N}");
            Directory.CreateDirectory(root);
            var previousExecutable = Path.Combine(root, "previous.exe");
            var currentExecutable = Path.Combine(root, "current.exe");
            var dataFile = Path.Combine(root, "data.yml");
            var outputDirectory = Path.Combine(root, "output");

            var previousBuilder = SyntheticPeBuilder.Create()
                .WithSection(".text", 0x1000, previousText, executable: true);
            var currentBuilder = SyntheticPeBuilder.Create()
                .WithSection(".text", 0x1000, currentText, executable: true);
            if (withRuntimeFunctions) {
                previousBuilder.WithRuntimeFunctions(new RuntimeFunctionSpec(0x1000, checked(0x1000u + (uint)previousText.Length), 0));
                currentBuilder.WithRuntimeFunctions(new RuntimeFunctionSpec(0x1000, checked(0x1000u + (uint)currentText.Length), 0));
            }

            using var previousFixture = previousBuilder.Write();
            using var currentFixture = currentBuilder.Write();
            File.Copy(previousFixture.ExecutablePath, previousExecutable);
            File.Copy(currentFixture.ExecutablePath, currentExecutable);
            File.WriteAllText(dataFile, $$"""
                version: old
                globals: {}
                functions:
                  0x{{ImageBase + 0x1000:X}}: Test::Symbol
                classes: {}
                """, new UTF8Encoding(false));

            return new TestPatchPair(root, previousExecutable, currentExecutable, dataFile, outputDirectory, instructionDecoder ?? new IcedInstructionDecoder());
        }

        private sealed class TestSignatureInventory : ISignatureInventory {
            public ImmutableArray<SignatureDefinition> Load() =>
                [SignatureDefinition.Parse("FFXIVClientStructs.FFXIV.Test.Symbol", "40 53", [])];
        }
    }

    private sealed class ThrowingInstructionDecoder : IInstructionDecoder {
        public DecodeResult Decode(ReadOnlySpan<byte> bytes, Rva instructionRva) =>
            throw new InvalidOperationException("Decoder preflight failed.");
    }

    private sealed class GraphFailingInstructionDecoder : IInstructionDecoder {
        public DecodeResult Decode(ReadOnlySpan<byte> bytes, Rva instructionRva) {
            if (instructionRva == new Rva(0) && bytes.SequenceEqual(new byte[] { 0xC3 }))
                return new DecodeResult(true, new DecodedInstruction(
                    instructionRva,
                    [0xC3],
                    "Ret",
                    FlowControlKind.Return,
                    null,
                    null,
                    []), null);

            throw new InvalidOperationException("Decoder failed while building the graph.");
        }
    }
}
