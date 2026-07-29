using System.Collections.Immutable;
using FFXIVClientStructs.PatchAnalyzer.Binary;
using FFXIVClientStructs.PatchAnalyzer.Decoding;
using FFXIVClientStructs.PatchAnalyzer.Graph;
using FFXIVClientStructs.PatchAnalyzer.Tests.Fixtures;
using Xunit;

namespace FFXIVClientStructs.PatchAnalyzer.Tests.Graph;

public class CallGraphBuilderTests {
    [Fact]
    public void Build_StopsAtIndirectBranchWithoutDecodingEmbeddedTable() {
        var decoder = FakeInstructionDecoder.For([
            Instruction.At(0x1000, 2, FlowControlKind.ConditionalBranch, target: 0x1010),
            Instruction.At(0x1002, 5, FlowControlKind.DirectCall, target: 0x2000),
            Instruction.At(0x1007, 2, FlowControlKind.IndirectBranch),
            Instruction.InvalidAt(0x1009),
            Instruction.At(0x1010, 1, FlowControlKind.Return)
        ]);
        var context = TestImages.Function(0x1000, 0x1020);

        var graph = CallGraphBuilder.Build(context.Image, context.FunctionIndex, decoder);

        var function = Assert.Single(graph.Functions);
        Assert.False(function.IsSuspect);
        Assert.DoesNotContain(new Rva(0x1009), function.ReachableInstructions);
        Assert.Equal(new Rva(0x2000), Assert.Single(graph.DirectCalls).Target);
    }

    [Fact]
    public void Build_ReachableInvalidInstruction_MarksFunctionSuspect() {
        var decoder = FakeInstructionDecoder.For([
            Instruction.At(0x1000, 1, FlowControlKind.Next),
            Instruction.InvalidAt(0x1001)
        ]);
        var context = TestImages.Function(0x1000, 0x1010);

        var function = Assert.Single(
            CallGraphBuilder.Build(context.Image, context.FunctionIndex, decoder).Functions);

        Assert.True(function.IsSuspect);
        Assert.NotEmpty(function.Diagnostics);
    }

    [Fact]
    public void Build_TransactionalInstruction_TraversesAbortTargetAndFallthrough() {
        var decoder = FakeInstructionDecoder.For([
            Instruction.At(0x1000, 2, FlowControlKind.Transactional, target: 0x1010),
            Instruction.At(0x1002, 1, FlowControlKind.Return),
            Instruction.At(0x1010, 1, FlowControlKind.Return)
        ]);
        var context = TestImages.Function(0x1000, 0x1020);

        var function = Assert.Single(
            CallGraphBuilder.Build(context.Image, context.FunctionIndex, decoder).Functions);

        Assert.Equal([0x1000u, 0x1002u, 0x1010u], function.ReachableInstructions.Select(rva => rva.Value));
    }

    [Fact]
    public void Build_WithIcedDecoder_TraversesControlFlowWithoutDecodingEmbeddedTable() {
        var bytes = new byte[0x20];
        new byte[] { 0xE8, 0xFB, 0x0F, 0x00, 0x00 }.CopyTo(bytes.AsSpan(0x00, 0x05)); // call 0x2000
        new byte[] { 0x75, 0x09 }.CopyTo(bytes.AsSpan(0x05, 0x02)); // jne 0x1010
        new byte[] { 0xFF, 0x24, 0x25, 0, 0, 0, 0 }.CopyTo(bytes.AsSpan(0x07, 0x07)); // jmp qword ptr [0]
        new byte[] { 0x0F, 0xFF }.CopyTo(bytes.AsSpan(0x0E, 0x02)); // invalid table bytes
        bytes[0x10] = 0xC3; // ret

        using var fixture = SyntheticPeBuilder.Create()
            .WithSection(".text", 0x1000, bytes, executable: true)
            .WithRuntimeFunctions(new RuntimeFunctionSpec(0x1000, 0x1020, 0x3000))
            .Write();
        var image = PeImage.Open(fixture.ExecutablePath);

        var graph = CallGraphBuilder.Build(image, FunctionIndex.Build(image), new IcedInstructionDecoder());

        var function = Assert.Single(graph.Functions);
        Assert.False(function.IsSuspect);
        Assert.Equal([0x1000u, 0x1005u, 0x1007u, 0x1010u], function.ReachableInstructions.Select(rva => rva.Value));
        var edge = Assert.Single(graph.DirectCalls);
        Assert.Equal(new Rva(0x1000), edge.SourceFunction);
        Assert.Equal(new Rva(0x1000), edge.CallSite);
        Assert.Equal(new Rva(0x2000), edge.Target);
    }

    private static class Instruction {
        public static FakeInstructionSpec At(uint rva, int length, FlowControlKind flowControl, uint? target = null) {
            var instruction = new DecodedInstruction(
                new Rva(rva),
                ImmutableArray.CreateRange(new byte[length]),
                "Fake",
                flowControl,
                target is null ? null : new Rva(target.Value),
                null,
                []);
            return new FakeInstructionSpec(new Rva(rva), new DecodeResult(true, instruction, null));
        }

        public static FakeInstructionSpec InvalidAt(uint rva) =>
            new(new Rva(rva), new DecodeResult(false, null, "The instruction encoding is invalid."));
    }
}
