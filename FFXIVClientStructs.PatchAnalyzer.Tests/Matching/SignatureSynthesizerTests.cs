using System.Collections.Immutable;
using FFXIVClientStructs.PatchAnalyzer.Analysis;
using FFXIVClientStructs.PatchAnalyzer.Binary;
using FFXIVClientStructs.PatchAnalyzer.Decoding;
using FFXIVClientStructs.PatchAnalyzer.Matching;
using FFXIVClientStructs.PatchAnalyzer.Signatures;
using FFXIVClientStructs.PatchAnalyzer.Tests.Fixtures;
using Xunit;

namespace FFXIVClientStructs.PatchAnalyzer.Tests.Matching;

public class SignatureSynthesizerTests {
    [Fact]
    public void Synthesize_GrowsByWholeInstructionsUntilEntryIsUnique() {
        var context = TestSynthesis.TwoFunctionsSharingFirstInstruction();

        var proposal = context.Synthesizer.Synthesize(
            context.Image,
            new Rva(0x1100),
            recoveryCallSite: null);

        Assert.NotNull(proposal);
        Assert.Equal(new Rva(0x1100), proposal.ResolvedRva);
        Assert.Empty(proposal.RelativeFollowOffsets);
        Assert.True(proposal.ByteLength > context.FirstInstructionLength);
    }

    [Fact]
    public void Synthesize_EntryRemainsAmbiguous_UsesLeadingCallSignature() {
        var context = TestSynthesis.AmbiguousEntryWithUniqueCallSite();

        var proposal = context.Synthesizer.Synthesize(
            context.Image,
            new Rva(0x1800),
            new Rva(0x1240));

        Assert.StartsWith("E8 ", proposal!.PatternText, StringComparison.Ordinal);
        Assert.Equal(new ushort[] { 1 }, proposal.RelativeFollowOffsets);
        Assert.Equal(new Rva(0x1800), proposal.ResolvedRva);
    }

    [Fact]
    public void RevalidateRecovered_ValidProposalRetainsRecoveredStatus() {
        var context = TestSynthesis.TwoFunctionsSharingFirstInstruction();

        var analysis = CandidateClassifier.RevalidateRecovered(
            RecoveredAnalysis(SymbolStatus.StructuralRecovered, 0x1100),
            context.Image,
            context.FunctionIndex,
            context.Decoder);

        Assert.Equal(SymbolStatus.StructuralRecovered, analysis.Status);
        Assert.Equal(new Rva(0x1100), analysis.CurrentTarget);
        Assert.NotNull(analysis.SuggestedSignature);
    }

    [Fact]
    public void RevalidateRecovered_InvalidProposalDowngradesAndClearsSuggestion() {
        var context = TestSynthesis.AmbiguousEntryWithUniqueCallSite();

        var analysis = CandidateClassifier.RevalidateRecovered(
            RecoveredAnalysis(SymbolStatus.StructuralRecovered, 0x1800),
            context.Image,
            context.FunctionIndex,
            context.Decoder);

        Assert.Equal(SymbolStatus.Missing, analysis.Status);
        Assert.Null(analysis.CurrentTarget);
        Assert.Null(analysis.SuggestedSignature);
        Assert.Contains(analysis.Diagnostics, diagnostic => diagnostic.Contains("0x1800", StringComparison.Ordinal));
    }

    private static SymbolAnalysis RecoveredAnalysis(SymbolStatus status, uint target) => new(
        "Test.Recovered",
        null,
        null,
        SignatureDefinition.Parse("Test.Recovered", "40 53", []),
        new Rva(target),
        new SignatureScanResult([], false, []),
        new SignatureScanResult([], false, []),
        status,
        new Rva(target),
        ImmutableArray<RecoveryEvidence>.Empty,
        null,
        ImmutableArray<string>.Empty);

    private static class TestSynthesis {
        public static TestSynthesisContext TwoFunctionsSharingFirstInstruction() {
            var bytes = new byte[0x1000];
            Write(bytes, 0x1100, [0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, 0xC3]);
            Write(bytes, 0x1200, [0x40, 0x53, 0x48, 0x83, 0xEC, 0x28, 0xC3]);

            return Create(bytes, [
                new RuntimeFunctionSpec(0x1100, 0x1107, 0x3000),
                new RuntimeFunctionSpec(0x1200, 0x1207, 0x3004)
            ], firstInstructionLength: 2);
        }

        public static TestSynthesisContext AmbiguousEntryWithUniqueCallSite() {
            var bytes = new byte[0x1000];
            Write(bytes, 0x1240, Call(0x1240, 0x1800));
            Write(bytes, 0x1245, [0x48, 0x83, 0xEC, 0x20, 0xC3]);
            Write(bytes, 0x1800, [0x40, 0x53, 0xC3]);
            Write(bytes, 0x1900, [0x40, 0x53, 0xC3]);

            return Create(bytes, [
                new RuntimeFunctionSpec(0x1200, 0x124A, 0x3000),
                new RuntimeFunctionSpec(0x1800, 0x1803, 0x3004),
                new RuntimeFunctionSpec(0x1900, 0x1903, 0x3008)
            ], firstInstructionLength: 2);
        }

        private static TestSynthesisContext Create(byte[] bytes, RuntimeFunctionSpec[] functions, int firstInstructionLength) {
            using var fixture = SyntheticPeBuilder.Create()
                .WithSection(".text", 0x1000, bytes, executable: true)
                .WithRuntimeFunctions(functions)
                .Write();
            var image = PeImage.Open(fixture.ExecutablePath);
            var functionIndex = FunctionIndex.Build(image);
            var decoder = new IcedInstructionDecoder();
            var synthesizer = new SignatureSynthesizer(functionIndex, decoder);
            return new TestSynthesisContext(image, functionIndex, decoder, synthesizer, firstInstructionLength);
        }

        private static byte[] Call(uint callSite, uint target) => [
            0xE8,
            .. BitConverter.GetBytes(checked((int)(target - (callSite + 5))))
        ];

        private static void Write(byte[] bytes, uint rva, byte[] value) =>
            value.CopyTo(bytes, checked((int)(rva - 0x1000)));
    }

    private sealed record TestSynthesisContext(
        PeImage Image,
        FunctionIndex FunctionIndex,
        IInstructionDecoder Decoder,
        SignatureSynthesizer Synthesizer,
        int FirstInstructionLength);
}
