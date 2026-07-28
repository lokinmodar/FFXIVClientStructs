using FFXIVClientStructs.PatchAnalyzer.Binary;
using FFXIVClientStructs.PatchAnalyzer.Decoding;
using FFXIVClientStructs.PatchAnalyzer.Graph;
using System.Collections.Immutable;
using Xunit;

namespace FFXIVClientStructs.PatchAnalyzer.Tests.Graph;

public class CallSiteFingerprintTests {
    [Fact]
    public void Create_IgnoresBranchAndRipRelativeDisplacements() {
        var oldWindow = TestInstructions.CallWindow(callDisplacement: 0x10, ripDisplacement: 0x20);
        var newWindow = TestInstructions.CallWindow(callDisplacement: 0x70, ripDisplacement: 0x90);

        Assert.Equal(
            CallSiteFingerprint.Create(oldWindow).Sha256,
            CallSiteFingerprint.Create(newWindow).Sha256);
    }

    [Fact]
    public void Create_PreservesSmallScalarImmediateAndStackDisplacement() {
        var original = TestInstructions.WindowWithScalarAndStackOffsets(scalar: 4, stackOffset: 0x20);
        var changed = TestInstructions.WindowWithScalarAndStackOffsets(scalar: 8, stackOffset: 0x28);

        Assert.NotEqual(
            CallSiteFingerprint.Create(original).Sha256,
            CallSiteFingerprint.Create(changed).Sha256);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(3)]
    [InlineData(5)]
    public void Create_RequiresExactlyFourInstructionsOnEachSide(int radius) {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            CallSiteFingerprint.Create(TestInstructions.NineInstructionFunction(), new Rva(0x1004), radius));
    }

    [Fact]
    public void Create_UsesFourInstructionsOnEachSideWhenAvailable() {
        var fingerprint = CallSiteFingerprint.Create(
            TestInstructions.NineInstructionFunction(),
            new Rva(0x1004),
            CallSiteFingerprint.InstructionRadius);

        Assert.Equal(9, fingerprint.InstructionCount);
    }

    private static class TestInstructions {
        public static DecodedInstruction[] CallWindow(byte callDisplacement, byte ripDisplacement) => [
            Instruction(0x1000, [0x48, 0x8B, 0x05, ripDisplacement, 0, 0, 0], "Mov_Register_Memory", FlowControlKind.Next,
                [new(new ByteRange(3, 4), EncodedConstantKind.IpRelativeDisplacement, ripDisplacement)]),
            Instruction(0x1007, [0xE8, callDisplacement, 0, 0, 0], "Call_NearBranch", FlowControlKind.DirectCall,
                [new(new ByteRange(1, 4), EncodedConstantKind.BranchDisplacement, callDisplacement)]),
            Instruction(0x100C, [0x48, 0x83, 0xC4, 0x20], "Add_Register_Immediate", FlowControlKind.Next,
                [new(new ByteRange(3, 1), EncodedConstantKind.Immediate, 0x20)])
        ];

        public static DecodedInstruction[] WindowWithScalarAndStackOffsets(byte scalar, byte stackOffset) => [
            Instruction(0x1000, [0x48, 0x83, 0xEC, stackOffset], "Sub_Register_Immediate", FlowControlKind.Next,
                [new(new ByteRange(3, 1), EncodedConstantKind.Displacement, stackOffset)]),
            Instruction(0x1004, [0xE8, 0, 0, 0, 0], "Call_NearBranch", FlowControlKind.DirectCall,
                [new(new ByteRange(1, 4), EncodedConstantKind.BranchDisplacement, 0)]),
            Instruction(0x1009, [0x83, 0xF8, scalar], "Cmp_Register_Immediate", FlowControlKind.Next,
                [new(new ByteRange(2, 1), EncodedConstantKind.Immediate, scalar)])
        ];

        public static FunctionGraph NineInstructionFunction() => new(
            new RuntimeFunctionRange(new Rva(0x1000), new Rva(0x1010), new Rva(0x2000)),
            false,
            ImmutableArray.CreateRange(Enumerable.Range(0, 9).Select(index => Instruction(
                (uint)(0x1000 + index),
                [0x90],
                index == 4 ? "Call_NearBranch" : "Nop",
                index == 4 ? FlowControlKind.DirectCall : FlowControlKind.Next,
                index == 4 ? [new DecodedConstant(new ByteRange(0, 1), EncodedConstantKind.BranchDisplacement, 0)] : []))),
            []);

        private static DecodedInstruction Instruction(
            uint rva,
            byte[] bytes,
            string opcodeKey,
            FlowControlKind flowControl,
            DecodedConstant[] constants) => new(
            new Rva(rva),
            [.. bytes],
            opcodeKey,
            flowControl,
            null,
            null,
            [.. constants]);
    }
}
