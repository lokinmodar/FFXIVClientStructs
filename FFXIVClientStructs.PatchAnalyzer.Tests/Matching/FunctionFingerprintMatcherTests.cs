using System.Collections.Immutable;
using FFXIVClientStructs.PatchAnalyzer.Analysis;
using FFXIVClientStructs.PatchAnalyzer.Binary;
using FFXIVClientStructs.PatchAnalyzer.Decoding;
using FFXIVClientStructs.PatchAnalyzer.Graph;
using FFXIVClientStructs.PatchAnalyzer.Matching;
using Xunit;

namespace FFXIVClientStructs.PatchAnalyzer.Tests.Matching;

public class FunctionFingerprintMatcherTests {
    [Fact]
    public void Match_ExactUniqueNormalizedFunction_ReturnsStructuralTarget() {
        var result = FunctionFingerprintMatcher.Match(
            TestFunctions.PreviousTarget(),
            TestFunctions.CurrentExactTargetAndUnrelatedFunctions());

        Assert.Equal(SymbolStatus.StructuralRecovered, result.Status);
        Assert.Equal(new Rva(0x2800), result.CurrentTarget);
        Assert.Equal(2, result.Candidates.Length);
        Assert.Contains(result.Candidates, candidate =>
            candidate.CurrentTarget == new Rva(0x3000) &&
            candidate.RejectionReason == "A unique exact fingerprint match was selected.");
    }

    [Fact]
    public void Match_RepeatedSmallFunctionShape_RemainsAmbiguous() {
        var result = FunctionFingerprintMatcher.Match(
            TestFunctions.PreviousNineInstructionWrapper(),
            TestFunctions.CurrentRepeatedWrappers(count: 3));

        Assert.Equal(SymbolStatus.Ambiguous, result.Status);
    }

    [Fact]
    public void Rank_FuzzyCandidates_DoesNotUseRvaDistanceOrGrantRecovery() {
        var result = FunctionFingerprintMatcher.Match(
            TestFunctions.PreviousTarget(),
            TestFunctions.CurrentSimilarTargetsAtSwappedRvas());

        Assert.NotEqual(SymbolStatus.StructuralRecovered, result.Status);
        Assert.All(result.Candidates, candidate => Assert.False(candidate.Exact));
    }

    [Fact]
    public void Create_NormalizesRelocatableOperandsButPreservesMemberOffsets() {
        var oldFunction = TestFunctions.WithRelocatableOperands(
            callTarget: 0x1800,
            ripTarget: 0x9000,
            memberOffset: 0x20);
        var movedFunction = TestFunctions.WithRelocatableOperands(
            callTarget: 0x3800,
            ripTarget: 0xB000,
            memberOffset: 0x20);
        var changedLayout = TestFunctions.WithRelocatableOperands(
            callTarget: 0x3800,
            ripTarget: 0xB000,
            memberOffset: 0x28);

        Assert.Equal(
            FunctionFingerprintMatcher.Create(oldFunction).Sha256,
            FunctionFingerprintMatcher.Create(movedFunction).Sha256);
        Assert.NotEqual(
            FunctionFingerprintMatcher.Create(oldFunction).Sha256,
            FunctionFingerprintMatcher.Create(changedLayout).Sha256);
    }

    [Fact]
    public void Rank_EqualDiagnosticScores_HasDeterministicOrder() {
        var result = FunctionFingerprintMatcher.Match(
            TestFunctions.PreviousTarget(),
            TestFunctions.EqualScoreCandidatesInReverseInputOrder());

        Assert.Equal(
            result.Candidates.OrderBy(candidate => candidate.CurrentTarget),
            result.Candidates);
    }

    [Fact]
    public void Match_SuspectExactFunction_DoesNotRecoverAndRecordsRejection() {
        var result = FunctionFingerprintMatcher.Match(
            TestFunctions.PreviousTarget(),
            TestFunctions.CurrentSuspectExactTarget());

        var candidate = Assert.Single(result.Candidates);
        Assert.NotEqual(SymbolStatus.StructuralRecovered, result.Status);
        Assert.True(candidate.Exact);
        Assert.Equal("The current function graph is suspect.", candidate.RejectionReason);
    }

    [Fact]
    public void Match_RetainsZeroScoreCandidateWithRejectionReason() {
        var result = FunctionFingerprintMatcher.Match(
            TestFunctions.PreviousTarget(),
            TestFunctions.CurrentUnrelatedFunction());

        var candidate = Assert.Single(result.Candidates);
        Assert.Equal(SymbolStatus.Missing, result.Status);
        Assert.False(candidate.Exact);
        Assert.Equal("The function has no structural similarity to the previous function.", candidate.RejectionReason);
    }

    private static class TestFunctions {
        public static FunctionGraph PreviousTarget() => Target(0x1000, callTarget: 0x1800, ripTarget: 0x9000, memberOffset: 0x20);

        public static CallGraph CurrentExactTargetAndUnrelatedFunctions() => Graph(
            Target(0x2800, callTarget: 0x4800, ripTarget: 0xB000, memberOffset: 0x20),
            Wrapper(0x3000));

        public static FunctionGraph PreviousNineInstructionWrapper() => Wrapper(0x1100);

        public static CallGraph CurrentRepeatedWrappers(int count) => Graph(
            Enumerable.Range(0, count).Select(index => Wrapper((uint)(0x2100 + index * 0x100))).ToArray());

        public static CallGraph CurrentSimilarTargetsAtSwappedRvas() => Graph(
            SimilarTarget(0x5000, extraInstruction: true),
            SimilarTarget(0x1800, extraInstruction: false));

        public static FunctionGraph WithRelocatableOperands(uint callTarget, uint ripTarget, ulong memberOffset) =>
            Target(0x1200, callTarget, ripTarget, memberOffset);

        public static CallGraph EqualScoreCandidatesInReverseInputOrder() => Graph(
            SimilarTarget(0x5000, extraInstruction: true),
            SimilarTarget(0x2000, extraInstruction: true));

        public static CallGraph CurrentSuspectExactTarget() => Graph(Target(0x2800, 0x4800, 0xB000, 0x20) with { IsSuspect = true });

        public static CallGraph CurrentUnrelatedFunction() => Graph(Function(0x2800, [
            Instruction(0x2800, "int3", FlowControlKind.Interrupt)
        ]));

        private static FunctionGraph Target(uint begin, uint callTarget, uint ripTarget, ulong memberOffset) => Function(begin, [
            Instruction(begin, "push", FlowControlKind.Next),
            Instruction(begin + 1, "mov-rip", FlowControlKind.Next, ipRelativeTarget: ripTarget,
                constants: [Constant(EncodedConstantKind.IpRelativeDisplacement, ripTarget)]),
            Instruction(begin + 8, "call", FlowControlKind.DirectCall, nearBranchTarget: callTarget,
                constants: [Constant(EncodedConstantKind.BranchDisplacement, callTarget)]),
            Instruction(begin + 13, "mov-member", FlowControlKind.Next,
                constants: [Constant(EncodedConstantKind.Displacement, memberOffset)]),
            Instruction(begin + 17, "jne", FlowControlKind.ConditionalBranch, nearBranchTarget: begin + 20,
                constants: [Constant(EncodedConstantKind.BranchDisplacement, begin + 20)]),
            Instruction(begin + 19, "xor", FlowControlKind.Next),
            Instruction(begin + 20, "ret", FlowControlKind.Return)
        ]);

        private static FunctionGraph SimilarTarget(uint begin, bool extraInstruction) {
            var instructions = Target(begin, begin + 0x800, begin + 0x900, 0x28).Instructions.ToList();
            if (extraInstruction)
                instructions[1] = instructions[1] with { OpcodeKey = "lea-rip" };
            return Function(begin, [.. instructions]);
        }

        private static FunctionGraph Wrapper(uint begin) => Function(begin, [
            Instruction(begin, "push", FlowControlKind.Next),
            Instruction(begin + 1, "mov", FlowControlKind.Next),
            Instruction(begin + 4, "mov", FlowControlKind.Next),
            Instruction(begin + 7, "test", FlowControlKind.Next),
            Instruction(begin + 9, "je", FlowControlKind.ConditionalBranch, nearBranchTarget: begin + 15,
                constants: [Constant(EncodedConstantKind.BranchDisplacement, begin + 15)]),
            Instruction(begin + 11, "call", FlowControlKind.DirectCall, nearBranchTarget: begin + 0x400,
                constants: [Constant(EncodedConstantKind.BranchDisplacement, begin + 0x400)]),
            Instruction(begin + 14, "pop", FlowControlKind.Next),
            Instruction(begin + 15, "ret", FlowControlKind.Return),
            Instruction(begin + 16, "int3", FlowControlKind.Interrupt)
        ]);

        private static CallGraph Graph(params FunctionGraph[] functions) => new([.. functions], []);

        private static FunctionGraph Function(uint begin, ImmutableArray<DecodedInstruction> instructions) => new(
            new RuntimeFunctionRange(new Rva(begin), new Rva(begin + 0x80), new Rva(begin + 0x100)),
            false,
            instructions,
            []);

        private static DecodedInstruction Instruction(
            uint rva,
            string opcodeKey,
            FlowControlKind flowControl,
            uint? nearBranchTarget = null,
            uint? ipRelativeTarget = null,
            ImmutableArray<DecodedConstant> constants = default) => new(
            new Rva(rva),
            [0x90],
            opcodeKey,
            flowControl,
            nearBranchTarget is null ? null : new Rva(nearBranchTarget.Value),
            ipRelativeTarget is null ? null : new Rva(ipRelativeTarget.Value),
            constants.IsDefault ? [] : constants);

        private static DecodedConstant Constant(EncodedConstantKind kind, ulong value) =>
            new(new ByteRange(0, 4), kind, value);
    }
}
