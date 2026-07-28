using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using FFXIVClientStructs.PatchAnalyzer.Analysis;
using FFXIVClientStructs.PatchAnalyzer.Binary;
using FFXIVClientStructs.PatchAnalyzer.Cli;
using FFXIVClientStructs.PatchAnalyzer.Decoding;
using FFXIVClientStructs.PatchAnalyzer.Graph;
using FFXIVClientStructs.PatchAnalyzer.Output;
using FFXIVClientStructs.PatchAnalyzer.Signatures;
using FFXIVClientStructs.PatchAnalyzer.Tests.Fixtures;
using Xunit;

namespace FFXIVClientStructs.PatchAnalyzer.Tests.Integration;

public class PatchAnalyzerApplicationTests {
    private const ulong ImageBase = 0x140000000;

    [Fact]
    public async Task RunAsync_OriginalSignatureMoves_ReturnsDirectUnique() {
        using var fixture = TestPatchPair.DirectUnique();

        var result = await RunSucceededAsync(fixture);

        AssertStatus(result, "FFXIVClientStructs.FFXIV.Test.Symbol", SymbolStatus.DirectUnique);
    }

    [Fact]
    public async Task RunAsync_ChangedPrologueWithUniqueNormalizedFunction_RecoversStructurally() {
        using var fixture = TestPatchPair.StructuralRecovered();

        var result = await RunSucceededAsync(fixture);

        AssertStatus(result, "FFXIVClientStructs.FFXIV.Test.Structural", SymbolStatus.StructuralRecovered);
    }

    [Fact]
    public async Task RunAsync_TwoStructurallyMappedCallersConverge_RecoversCaller() {
        using var fixture = TestPatchPair.CallerRecovered();

        var result = await RunSucceededAsync(fixture);

        AssertStatus(result, "FFXIVClientStructs.FFXIV.Test.Target", SymbolStatus.CallerRecovered);
    }

    [Fact]
    public async Task RunAsync_RepeatedSmallFunctionIdentity_RemainsAmbiguous() {
        using var fixture = TestPatchPair.RepeatedStructuralIdentity();

        var result = await RunSucceededAsync(fixture);

        AssertStatus(result, "FFXIVClientStructs.FFXIV.Test.Wrapper", SymbolStatus.Ambiguous);
    }

    [Fact]
    public async Task RunAsync_TwoEquivalentCurrentAnchors_RemainsAmbiguous() {
        using var fixture = TestPatchPair.AmbiguousDirectAnchors();

        var result = await RunSucceededAsync(fixture);

        AssertStatus(result, "FFXIVClientStructs.FFXIV.Test.Anchor", SymbolStatus.Ambiguous);
    }

    [Fact]
    public async Task RunAsync_DisappearedDirectCall_ReturnsPossibleInlining() {
        using var fixture = TestPatchPair.PossibleInlining();

        var result = await RunSucceededAsync(fixture);

        AssertStatus(result, "FFXIVClientStructs.FFXIV.Test.Target", SymbolStatus.PossibleInlining);
    }

    [Fact]
    public async Task RunAsync_OldSignatureConflictsWithYaml_ReturnsStaleSource() {
        using var fixture = TestPatchPair.StaleSource();

        var result = await RunSucceededAsync(fixture);

        AssertStatus(result, "FFXIVClientStructs.FFXIV.Test.Stale", SymbolStatus.StaleSource);
    }

    [Fact]
    public async Task RunAsync_CallSiteSignatureWithRelativeFollowOffset_ResolvesTarget() {
        using var fixture = TestPatchPair.RelativeFollow();

        var result = await RunSucceededAsync(fixture);

        var symbol = AssertStatus(result, "FFXIVClientStructs.FFXIV.Test.Relative", SymbolStatus.DirectUnique);
        Assert.Equal(0x1020u, symbol.CurrentTargetRva);
        Assert.Equal(new ushort[] { 1 }, symbol.RelativeFollowOffsets);
    }

    [Fact]
    public async Task RunAsync_CandidateYaml_PreservesCommentsOrderAndBlankLines() {
        using var fixture = TestPatchPair.DirectUnique(source: """
            # retained comment
            version: old # version comment
            globals: {}

            functions:
              0x140001000: Test::Symbol # retained function comment
            classes: {}
            """);

        await RunSucceededAsync(fixture);

        var candidate = File.ReadAllText(fixture.CandidateYamlPath);
        Assert.Contains("# retained comment\nversion: old # version comment\nglobals: {}\n\nfunctions:", candidate, StringComparison.Ordinal);
        Assert.Contains("0x140001020: Test::Symbol # retained function comment", candidate, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RunAsync_DifferentElapsedTimings_ProduceByteIdenticalArtifacts() {
        using var fixture = TestPatchPair.DirectUnique(new DelayedInstructionDecoder());
        var firstOutput = Path.Combine(fixture.Root, "first");
        var secondOutput = Path.Combine(fixture.Root, "second");

        await RunSucceededAsync(fixture, firstOutput);
        await RunSucceededAsync(fixture, secondOutput);

        Assert.Equal(File.ReadAllBytes(Path.Combine(firstOutput, "report.json")), File.ReadAllBytes(Path.Combine(secondOutput, "report.json")));
        Assert.Equal(File.ReadAllBytes(Path.Combine(firstOutput, "data.candidate.yml")), File.ReadAllBytes(Path.Combine(secondOutput, "data.candidate.yml")));
    }

    [Fact]
    public async Task RunAsync_TrustedUnreachableCallSiteSeedsBoundedRecovery() {
        using var fixture = TestPatchPair.TrustedUnreachableCallSite();

        var result = await RunSucceededAsync(fixture);

        var symbol = AssertStatus(result, "FFXIVClientStructs.FFXIV.Test.Dispatch", SymbolStatus.CallerRecovered);
        Assert.Contains(symbol.RecoveryEvidence, evidence => evidence.AnchorKind == "TrustedCallSite");

        var graph = CallGraphBuilder.Build(PeImage.Open(fixture.PreviousExecutable), FunctionIndex.Build(PeImage.Open(fixture.PreviousExecutable)), fixture.Decoder);
        Assert.DoesNotContain(new Rva(0x1014), Assert.Single(graph.Functions).ReachableInstructions);
    }

    [Fact]
    public async Task RunAsync_ReachableInvalidInstruction_IsolatesAnalysisError() {
        using var fixture = TestPatchPair.ReachableInvalidInstruction();

        var result = await RunSucceededAsync(fixture);

        AssertStatus(result, "FFXIVClientStructs.FFXIV.Test.Bad", SymbolStatus.AnalysisError);
        AssertStatus(result, "FFXIVClientStructs.FFXIV.Test.Good", SymbolStatus.DirectUnique);
    }

    [Fact]
    public async Task RunAsync_IdenticalExecutables_ReturnsInvalidInputWithoutArtifacts() {
        using var fixture = TestPatchPair.SameExecutable();

        var exitCode = await fixture.Application.RunAsync(fixture.Options, CancellationToken.None);

        Assert.Equal(ExitCode.InvalidInput, exitCode);
        Assert.False(File.Exists(fixture.ReportPath));
    }

    private static readonly JsonSerializerOptions ReportOptions = new() {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        PropertyNameCaseInsensitive = true,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.SnakeCaseLower) }
    };

    private static async Task<AnalysisReport> RunSucceededAsync(TestPatchPair fixture, string? outputDirectory = null) {
        var exitCode = await fixture.Application.RunAsync(outputDirectory is null ? fixture.Options : fixture.OptionsFor(outputDirectory), CancellationToken.None);
        Assert.Equal(ExitCode.Success, exitCode);

        var reportPath = Path.Combine(outputDirectory ?? fixture.OutputDirectory, "report.json");
        var result = JsonSerializer.Deserialize<AnalysisReport>(File.ReadAllText(reportPath), ReportOptions);
        Assert.NotNull(result);
        AssertInventory(fixture, result);
        return result;
    }

    private static void AssertInventory(TestPatchPair fixture, AnalysisReport result) {
        Assert.Equal(
            fixture.Inventory.Length,
            result.Symbols.Length);
        Assert.Equal(
            fixture.Inventory.Length,
            result.Symbols.GroupBy(symbol => symbol.Status).Sum(group => group.Count()));
        Assert.Empty(
            fixture.Inventory.Select(item => item.GeneratedName)
                .Except(result.Symbols.Select(symbol => symbol.GeneratedName), StringComparer.Ordinal));
    }

    private static ReportSymbol AssertStatus(AnalysisReport result, string generatedName, SymbolStatus status) {
        var symbol = Assert.Single(result.Symbols, item => item.GeneratedName == generatedName);
        Assert.Equal(status, symbol.Status);
        return symbol;
    }

    private sealed class TestPatchPair : IDisposable {
        private readonly string root;

        private TestPatchPair(string root, string previousExecutable, string currentExecutable, string dataFile, string outputDirectory, ImmutableArray<SignatureDefinition> inventory, IInstructionDecoder decoder) {
            this.root = root;
            Root = root;
            PreviousExecutable = previousExecutable;
            CurrentExecutable = currentExecutable;
            DataFile = dataFile;
            OutputDirectory = outputDirectory;
            Inventory = inventory;
            Decoder = decoder;
            Options = OptionsFor(outputDirectory);
            Application = new PatchAnalyzerApplication(new TestSignatureInventory(inventory), decoder);
        }

        public PatchAnalyzerApplication Application { get; }
        public IInstructionDecoder Decoder { get; }
        public ImmutableArray<SignatureDefinition> Inventory { get; }
        public AnalyzerOptions Options { get; }
        public string Root { get; }
        public string PreviousExecutable { get; }
        public string CurrentExecutable { get; }
        public string DataFile { get; }
        public string OutputDirectory { get; }
        public string ReportPath => Path.Combine(OutputDirectory, "report.json");
        public string CandidateYamlPath => Path.Combine(OutputDirectory, "data.candidate.yml");

        public AnalyzerOptions OptionsFor(string outputDirectory) => new(PreviousExecutable, CurrentExecutable, DataFile, outputDirectory, null, null);

        public static TestPatchPair SameExecutable() => Create([0x40, 0x53, 0xC3], [0x40, 0x53, 0xC3], [Signature("Symbol", "40 53")], Yaml((0x1000, "Test::Symbol")));

        public static TestPatchPair DirectUnique(IInstructionDecoder? decoder = null, string? source = null) => Create(
            Bytes(0x40, (0, [0x40, 0x53, 0xC3])),
            Bytes(0x40, (0x20, [0x40, 0x53, 0xC3])),
            [Signature("Symbol", "40 53")],
            source ?? Yaml((0x1000, "Test::Symbol")),
            decoder: decoder);

        public static TestPatchPair StructuralRecovered() {
            var previous = Bytes(0x300);
            var current = Bytes(0x300);
            WriteCall(previous, 0, 0x1000, 0x1140);
            previous[5] = 0xC3;
            WriteCall(current, 0x80, 0x1080, 0x1150);
            current[0x85] = 0xC3;
            return Create(previous, current, [Signature("Structural", Pattern(previous, 0, 5))], Yaml((0x1000, "Test::Structural")),
                [new RuntimeFunctionSpec(0x1000, 0x1006, 0)], [new RuntimeFunctionSpec(0x1080, 0x1086, 0)]);
        }

        public static TestPatchPair CallerRecovered() {
            var previous = Bytes(0x1A00);
            var current = Bytes(0x1A00);
            Place(previous, 0x1000, Caller(0x1000, 0x1500, 0xC3));
            Place(previous, 0x1100, Caller(0x1100, 0x1500, 0xCC));
            Place(previous, 0x1500, [0x55, 0xC3]);
            Place(current, 0x2000, Caller(0x2000, 0x2800, 0xC3));
            Place(current, 0x2100, Caller(0x2100, 0x2800, 0xCC));
            Place(current, 0x2800, [0x48, 0x83, 0xEC, 0x28, 0xC3]);
            return Create(previous, current, [Signature("Target", "55 C3")], Yaml((0x1500, "Test::Target")),
                [new RuntimeFunctionSpec(0x1000, 0x100E, 0), new RuntimeFunctionSpec(0x1100, 0x110E, 0), new RuntimeFunctionSpec(0x1500, 0x1502, 0)],
                [new RuntimeFunctionSpec(0x2000, 0x200E, 0), new RuntimeFunctionSpec(0x2100, 0x210E, 0), new RuntimeFunctionSpec(0x2800, 0x2805, 0)]);
        }

        public static TestPatchPair RepeatedStructuralIdentity() {
            var previous = Bytes(0x700);
            var current = Bytes(0x700);
            WriteCall(previous, 0, 0x1000, 0x1100);
            previous.AsSpan(5, 7).Fill(0x90);
            previous[12] = 0xC3;
            WriteCall(current, 0x200, 0x1200, 0x1400);
            current.AsSpan(0x205, 7).Fill(0x90);
            current[0x20C] = 0xC3;
            WriteCall(current, 0x300, 0x1300, 0x1500);
            current.AsSpan(0x305, 7).Fill(0x90);
            current[0x30C] = 0xC3;
            return Create(previous, current, [Signature("Wrapper", "E8 ?? ?? ?? ??")], Yaml((0x1000, "Test::Wrapper")),
                [new RuntimeFunctionSpec(0x1000, 0x100D, 0)], [new RuntimeFunctionSpec(0x1200, 0x120D, 0), new RuntimeFunctionSpec(0x1300, 0x130D, 0)]);
        }

        public static TestPatchPair AmbiguousDirectAnchors() => Create(
            Bytes(0x40, (0, [0x40, 0x53, 0xC3])),
            Bytes(0x40, (0, [0x40, 0x53, 0xC3]), (0x20, [0x40, 0x53, 0xC3])),
            [Signature("Anchor", "40 53")], Yaml((0x1000, "Test::Anchor")));

        public static TestPatchPair PossibleInlining() {
            var previous = Bytes(0x700);
            var current = Bytes(0x700);
            Place(previous, 0x1000, [0x40, 0x53, 0x90, 0x90, 0x90, 0x90]);
            WriteCall(previous, 6, 0x1006, 0x1500);
            previous[11] = 0xC3;
            Place(previous, 0x1500, [0x55, 0x56, 0xC3]);
            Place(current, 0x1100, [0x40, 0x53, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xC3]);
            return Create(previous, current, [Signature("Caller", "40 53"), Signature("Target", "55 56")],
                Yaml((0x1000, "Test::Caller"), (0x1500, "Test::Target")),
                [new RuntimeFunctionSpec(0x1000, 0x100C, 0)], [new RuntimeFunctionSpec(0x1100, 0x1109, 0)]);
        }

        public static TestPatchPair StaleSource() => Create(
            Bytes(0x40, (0, [0x40, 0x53, 0xC3])), Bytes(0x40, (0x20, [0x40, 0x53, 0xC3])),
            [Signature("Stale", "40 53")], Yaml((0x1010, "Test::Stale")));

        public static TestPatchPair RelativeFollow() {
            var previous = Bytes(0x40);
            var current = Bytes(0x40);
            WriteCall(previous, 0, 0x1000, 0x1010);
            previous[0x10] = 0xC3;
            WriteCall(current, 0, 0x1000, 0x1020);
            current[0x20] = 0xC3;
            return Create(previous, current, [Signature("Relative", "E8 ?? ?? ?? ??", [1])], Yaml((0x1010, "Test::Relative")));
        }

        public static TestPatchPair TrustedUnreachableCallSite() {
            var previous = Bytes(0x1300);
            var current = Bytes(0x1300);
            Place(previous, 0x1000, Dispatch(0x1000, 0x1100));
            Place(current, 0x1000, Dispatch(0x1000, 0x1200));
            var callPattern = Pattern(previous, 0x14, 5);
            return Create(previous, current, [Signature("Dispatch", callPattern, [1])], Yaml((0x1100, "Test::Dispatch")),
                [new RuntimeFunctionSpec(0x1000, 0x101E, 0)], [new RuntimeFunctionSpec(0x1000, 0x101E, 0)]);
        }

        public static TestPatchPair ReachableInvalidInstruction() => Create(
            Bytes(0x80, (0, [0x0F, 0xFF]), (0x20, [0x40, 0x53, 0xC3])),
            Bytes(0x80, (0, [0x0F, 0xFF]), (0x30, [0x40, 0x53, 0xC3])),
            [Signature("Bad", "0F FF"), Signature("Good", "40 53")],
            Yaml((0x1000, "Test::Bad"), (0x1020, "Test::Good")),
            [new RuntimeFunctionSpec(0x1000, 0x1002, 0)], [new RuntimeFunctionSpec(0x1000, 0x1002, 0)]);

        public void Dispose() {
            if (Directory.Exists(root))
                Directory.Delete(root, recursive: true);
        }

        private static TestPatchPair Create(
            byte[] previousText,
            byte[] currentText,
            SignatureDefinition[] inventory,
            string source,
            RuntimeFunctionSpec[]? previousFunctions = null,
            RuntimeFunctionSpec[]? currentFunctions = null,
            IInstructionDecoder? decoder = null) {
            var root = Path.Combine(Path.GetTempPath(), $"FFXIVClientStructs.PatchAnalyzer.Tests.{Guid.NewGuid():N}");
            Directory.CreateDirectory(root);
            var previousExecutable = Path.Combine(root, "previous.exe");
            var currentExecutable = Path.Combine(root, "current.exe");
            var dataFile = Path.Combine(root, "data.yml");
            var outputDirectory = Path.Combine(root, "output");
            var previousBuilder = SyntheticPeBuilder.Create().WithSection(".text", 0x1000, previousText, executable: true);
            var currentBuilder = SyntheticPeBuilder.Create().WithSection(".text", 0x1000, currentText, executable: true);
            if (previousFunctions is { Length: > 0 })
                previousBuilder.WithRuntimeFunctions(previousFunctions);
            if (currentFunctions is { Length: > 0 })
                currentBuilder.WithRuntimeFunctions(currentFunctions);

            using var previousFixture = previousBuilder.Write();
            using var currentFixture = currentBuilder.Write();
            File.Copy(previousFixture.ExecutablePath, previousExecutable);
            File.Copy(currentFixture.ExecutablePath, currentExecutable);
            File.WriteAllText(dataFile, source, new UTF8Encoding(false));
            return new TestPatchPair(root, previousExecutable, currentExecutable, dataFile, outputDirectory, [.. inventory], decoder ?? new IcedInstructionDecoder());
        }

        private static SignatureDefinition Signature(string member, string pattern, ushort[]? relativeFollowOffsets = null) =>
            SignatureDefinition.Parse($"FFXIVClientStructs.FFXIV.Test.{member}", pattern, relativeFollowOffsets ?? []);

        private static string Yaml(params (uint Rva, string Name)[] functions) => "version: old\nglobals: {}\nfunctions:\n" +
            string.Concat(functions.Select(function => $"  0x{ImageBase + function.Rva:X}: {function.Name}\n")) + "classes: {}\n";

        private static byte[] Bytes(int length, params (int Offset, byte[] Data)[] segments) {
            var bytes = Enumerable.Repeat((byte)0xCC, length).ToArray();
            foreach (var (offset, data) in segments)
                data.CopyTo(bytes, offset);
            return bytes;
        }

        private static byte[] Caller(uint callerRva, uint targetRva, byte tail) {
            var bytes = Enumerable.Repeat((byte)0x90, 14).ToArray();
            WriteCall(bytes, 4, callerRva + 4, targetRva);
            bytes[^1] = tail;
            return bytes;
        }

        private static byte[] Dispatch(uint callerRva, uint targetRva) {
            var bytes = Enumerable.Repeat((byte)0x90, 0x1E).ToArray();
            WriteBranch(bytes, 0, callerRva, callerRva + 0x1D);
            WriteCall(bytes, 0x14, callerRva + 0x14, targetRva);
            bytes[0x1D] = 0xC3;
            return bytes;
        }

        private static void Place(byte[] destination, uint rva, byte[] bytes) => bytes.CopyTo(destination, checked((int)(rva - 0x1000)));

        private static void WriteCall(byte[] bytes, int offset, uint callRva, uint targetRva) {
            bytes[offset] = 0xE8;
            BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(offset + 1, 4), checked((int)(targetRva - callRva - 5)));
        }

        private static void WriteBranch(byte[] bytes, int offset, uint branchRva, uint targetRva) {
            bytes[offset] = 0xE9;
            BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(offset + 1, 4), checked((int)(targetRva - branchRva - 5)));
        }

        private static string Pattern(byte[] bytes, int offset, int length) => string.Join(" ", bytes.AsSpan(offset, length).ToArray().Select(value => value.ToString("X2")));

        private sealed class TestSignatureInventory(ImmutableArray<SignatureDefinition> inventory) : ISignatureInventory {
            public ImmutableArray<SignatureDefinition> Load() => inventory;
        }
    }

    private sealed class DelayedInstructionDecoder : IInstructionDecoder {
        private readonly IInstructionDecoder inner = new IcedInstructionDecoder();
        private int decodeCount;

        public DecodeResult Decode(ReadOnlySpan<byte> bytes, Rva instructionRva) {
            Thread.Sleep(Interlocked.Increment(ref decodeCount) % 2 == 0 ? 2 : 5);
            return inner.Decode(bytes, instructionRva);
        }
    }
}
