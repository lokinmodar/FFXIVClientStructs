using System.Collections.Immutable;
using FFXIVClientStructs.PatchAnalyzer.Analysis;
using FFXIVClientStructs.PatchAnalyzer.Binary;
using FFXIVClientStructs.PatchAnalyzer.Data;
using FFXIVClientStructs.PatchAnalyzer.Decoding;
using FFXIVClientStructs.PatchAnalyzer.Graph;
using FFXIVClientStructs.PatchAnalyzer.Matching;
using FFXIVClientStructs.PatchAnalyzer.Signatures;
using FFXIVClientStructs.PatchAnalyzer.Tests.Fixtures;
using Xunit;

namespace FFXIVClientStructs.PatchAnalyzer.Tests.Matching;

public class CallerRecoveryMatcherTests {
    [Fact]
    public void Recover_UniqueEquivalentCallSite_WithoutProposalDowngradesToMissing() {
        var result = CallerRecoveryMatcher.Recover(
            TestRecovery.MissingDirectTarget(0x1500),
            TestGraphs.OldIncomingCall(0x1200, 0x1230, 0x1500),
            TestGraphs.CurrentIncomingCall(0x2200, 0x2230, 0x2800),
            TestRecovery.SignedCallerAnchor(0x1200, 0x2200));

        Assert.Equal(SymbolStatus.Missing, result.Status);
        Assert.Null(result.CurrentTarget);
        Assert.Single(result.RecoveryEvidence, evidence => evidence.CurrentTarget == new Rva(0x2800));
    }

    [Fact]
    public void Recover_UniqueCallerEvidence_RevalidatesThroughCallSiteProposal() {
        var result = CallerRecoveryMatcher.Recover(
            TestRecovery.MissingDirectTarget(0x1500),
            TestGraphs.OldIncomingCall(0x1200, 0x1230, 0x1500),
            TestGraphs.CurrentIncomingCall(0x2200, 0x2230, 0x2800),
            TestRecovery.SignedCallerAnchor(0x1200, 0x2200, TestRecovery.CurrentImageWithAmbiguousTargetAndUniqueCall()));

        Assert.Equal(SymbolStatus.CallerRecovered, result.Status);
        Assert.Equal(new Rva(0x2800), result.CurrentTarget);
        Assert.NotNull(result.SuggestedSignature);
        Assert.Equal(new ushort[] { 1 }, result.SuggestedSignature.RelativeFollowOffsets);
    }

    [Fact]
    public void Recover_TwoStructurallyMappedCallersConverge_WithoutProposalDowngradesToMissing() {
        var result = CallerRecoveryMatcher.Recover(
            TestRecovery.MissingDirectTarget(0x1500),
            TestGraphs.TwoOldCallersOf(0x1500),
            TestGraphs.TwoMappedCurrentCallersOf(0x2800),
            TestRecovery.StructuralCallerMatches(0x1200, 0x2200, 0x1300, 0x2300));

        Assert.Equal(SymbolStatus.Missing, result.Status);
        Assert.Null(result.CurrentTarget);
        Assert.Equal(2, result.RecoveryEvidence.Length);
    }

    [Fact]
    public void Recover_StructurallyMappedCallersDisagree_IsAmbiguous() {
        var result = CallerRecoveryMatcher.Recover(
            TestRecovery.MissingDirectTarget(0x1500),
            TestGraphs.TwoOldCallersOf(0x1500),
            TestGraphs.MappedCurrentCallersOf(0x2800, 0x2900),
            TestRecovery.StructuralCallerMatches(0x1200, 0x2200, 0x1300, 0x2300));

        Assert.Equal(SymbolStatus.Ambiguous, result.Status);
    }

    [Fact]
    public void Recover_NonUniqueExactCallerMapping_IsAmbiguous() {
        var result = CallerRecoveryMatcher.Recover(
            TestRecovery.MissingDirectTarget(0x1500),
            TestGraphs.OldIncomingCall(0x1200, 0x1230, 0x1500),
            TestGraphs.CurrentIncomingCall(0x2200, 0x2230, 0x2800),
            TestRecovery.NonUniqueStructuralCallerMatch(0x1200, 0x2200, 0x2300));

        Assert.Equal(SymbolStatus.Ambiguous, result.Status);
    }

    [Fact]
    public void Recover_TrustedOldCallSiteSeedsUnreachableDispatchBlock() {
        var previous = TestGraphs.DispatchBlockReachableOnlyFromTrustedCallSite(0x1230);
        var current = TestGraphs.UniqueEquivalentDispatchBlock(0x2230, target: 0x2800);
        var result = CallerRecoveryMatcher.Recover(
            TestRecovery.MissingCallSiteSignature(0x1230, target: 0x1500),
            previous,
            current,
            TestRecovery.TrustedDispatchContext());

        Assert.Equal(SymbolStatus.Missing, result.Status);
        Assert.Null(result.CurrentTarget);
        Assert.Single(result.RecoveryEvidence, evidence => evidence.CurrentTarget == new Rva(0x2800));
        Assert.DoesNotContain(new Rva(0x1230), Assert.Single(previous.Functions).ReachableInstructions);
        Assert.DoesNotContain(new Rva(0x2230), Assert.Single(current.Functions).ReachableInstructions);
    }

    [Fact]
    public void Recover_TrustedOldCallSiteWithoutFullWindow_ReturnsUnsupported() {
        var result = CallerRecoveryMatcher.Recover(
            TestRecovery.MissingCallSiteSignature(0x1230, target: 0x1500),
            TestGraphs.DispatchBlockReachableOnlyFromTrustedCallSite(0x1230),
            TestGraphs.UniqueEquivalentDispatchBlock(0x2230, target: 0x2800),
            TestRecovery.TrustedDispatchContext(previousHasFullWindow: false));

        Assert.Equal(SymbolStatus.Unsupported, result.Status);
    }

    [Fact]
    public void Recover_TrustedTailJumpWithPadding_ReturnsUnsupported() {
        var result = CallerRecoveryMatcher.Recover(
            TestRecovery.MissingCallSiteSignature(0x1230, target: 0x1500),
            TestGraphs.DispatchBlockReachableOnlyFromTrustedCallSite(0x1230),
            TestGraphs.UniqueEquivalentDispatchBlock(0x2230, target: 0x2800),
            TestRecovery.TrustedJumpContext());

        Assert.Equal(SymbolStatus.Unsupported, result.Status);
        Assert.Null(result.CurrentTarget);
    }

    [Fact]
    public void Recover_NormalizesImageRangeImmediatePointers() {
        var result = CallerRecoveryMatcher.Recover(
            TestRecovery.MissingDirectTarget(0x1500),
            TestGraphs.IncomingCallWithImagePointer(0x1200, 0x1230, 0x1500, pointer: 0x140001800),
            TestGraphs.IncomingCallWithImagePointer(0x2200, 0x2230, 0x2800, pointer: 0x140002800),
            TestRecovery.SignedCallerAnchor(0x1200, 0x2200));

        Assert.Equal(SymbolStatus.Missing, result.Status);
        Assert.Null(result.CurrentTarget);
        Assert.Single(result.RecoveryEvidence, evidence => evidence.CurrentTarget == new Rva(0x2800));
    }

    [Fact]
    public void Recover_PreservesSmallScalarImmediateWhenImageBoundsAreProvided() {
        var result = CallerRecoveryMatcher.Recover(
            TestRecovery.MissingDirectTarget(0x1500),
            TestGraphs.IncomingCallWithScalar(0x1200, 0x1230, 0x1500, scalar: 4),
            TestGraphs.IncomingCallWithScalar(0x2200, 0x2230, 0x2800, scalar: 8),
            TestRecovery.SignedCallerAnchor(0x1200, 0x2200));

        Assert.Equal(SymbolStatus.PossibleInlining, result.Status);
        Assert.Null(result.CurrentTarget);
    }

    [Fact]
    public void Recover_NonFunctionLocation_ReturnsUnsupported() {
        var result = CallerRecoveryMatcher.Recover(
            TestRecovery.MissingDirectTarget(0x1500, LocationKind.Global),
            TestGraphs.OldIncomingCall(0x1200, 0x1230, 0x1500),
            TestGraphs.CurrentIncomingCall(0x2200, 0x2230, 0x2800),
            TestRecovery.SignedCallerAnchor(0x1200, 0x2200));

        Assert.Equal(SymbolStatus.Unsupported, result.Status);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(3)]
    [InlineData(5)]
    public void Context_RequiresExactlyFourInstructionsOnEachSide(int radius) {
        Assert.Throws<ArgumentOutOfRangeException>(() => TestRecovery.ContextWithRadius(radius));
    }

    private static class TestRecovery {
        public static SymbolAnalysis MissingDirectTarget(uint target, LocationKind kind = LocationKind.Function) => Analysis(
            target,
            kind,
            SymbolStatus.Missing,
            new SignatureScanResult([], false, []));

        public static SymbolAnalysis MissingCallSiteSignature(uint callSite, uint target) => Analysis(
            target,
            LocationKind.Function,
            SymbolStatus.Missing,
            new SignatureScanResult([new SignatureMatch(new Rva(callSite), new Rva(target))], false, []));

        public static CallerRecoveryContext SignedCallerAnchor(uint oldCaller, uint currentCaller, PeImage? currentImage = null) => Context(
            4,
            new Dictionary<Rva, FunctionMatchResult>(),
            new Dictionary<Rva, SymbolAnalysis> {
                [new Rva(oldCaller)] = Analysis(oldCaller, LocationKind.Function, SymbolStatus.DirectUnique,
                    new SignatureScanResult([new SignatureMatch(new Rva(oldCaller), new Rva(oldCaller))], false, []),
                    new Rva(currentCaller))
            }, currentImage: currentImage);

        public static PeImage CurrentImageWithAmbiguousTargetAndUniqueCall() {
            var bytes = new byte[0x2000];
            var callOffset = checked((int)(0x2230 - 0x1000));
            bytes[callOffset] = 0xE8;
            BitConverter.GetBytes(checked((int)(0x2800 - 0x2235))).CopyTo(bytes, callOffset + 1);
            bytes[0x1800] = 0x40;
            bytes[0x1801] = 0x53;
            bytes[0x1802] = 0xC3;
            bytes[0x1900] = 0x40;
            bytes[0x1901] = 0x53;
            bytes[0x1902] = 0xC3;

            using var fixture = SyntheticPeBuilder.Create()
                .WithSection(".text", 0x1000, bytes, executable: true)
                .WithRuntimeFunctions(
                    new RuntimeFunctionSpec(0x2200, 0x2235, 0x3000),
                    new RuntimeFunctionSpec(0x2800, 0x2803, 0x3004),
                    new RuntimeFunctionSpec(0x2900, 0x2903, 0x3008))
                .Write();
            return PeImage.Open(fixture.ExecutablePath);
        }

        public static CallerRecoveryContext StructuralCallerMatches(uint oldFirst, uint currentFirst, uint oldSecond, uint currentSecond) => Context(
            4,
            new Dictionary<Rva, FunctionMatchResult> {
                [new Rva(oldFirst)] = ExactMatch(currentFirst),
                [new Rva(oldSecond)] = ExactMatch(currentSecond)
            },
            new Dictionary<Rva, SymbolAnalysis>());

        public static CallerRecoveryContext NonUniqueStructuralCallerMatch(uint oldCaller, uint firstCurrent, uint secondCurrent) => Context(
            4,
            new Dictionary<Rva, FunctionMatchResult> {
                [new Rva(oldCaller)] = new FunctionMatchResult(
                    SymbolStatus.Ambiguous,
                    null,
                    new FunctionFingerprint("exact", [], 0, 0),
                    [
                        new FunctionMatchCandidate(new Rva(firstCurrent), true, 1, "exact", "The exact fingerprint is not unique."),
                        new FunctionMatchCandidate(new Rva(secondCurrent), true, 2, "exact", "The exact fingerprint is not unique.")
                    ])
            },
            new Dictionary<Rva, SymbolAnalysis>());

        public static CallerRecoveryContext TrustedDispatchContext(bool previousHasFullWindow = true) => Context(
            4,
            new Dictionary<Rva, FunctionMatchResult> { [new Rva(0x1200)] = ExactMatch(0x2200) },
            new Dictionary<Rva, SymbolAnalysis>(),
            ImageWithDirectCall(0x1230, 0x1500, previousHasFullWindow),
            ImageWithDirectCall(0x2230, 0x2800, hasFullWindow: true));

        public static CallerRecoveryContext TrustedJumpContext() => Context(
            4,
            new Dictionary<Rva, FunctionMatchResult> { [new Rva(0x1200)] = ExactMatch(0x2200) },
            new Dictionary<Rva, SymbolAnalysis>(),
            ImageWithDirectJump(0x1230, 0x1500),
            ImageWithDirectJump(0x2230, 0x2800));

        public static CallerRecoveryContext ContextWithRadius(int radius) => Context(
            radius,
            new Dictionary<Rva, FunctionMatchResult>(),
            new Dictionary<Rva, SymbolAnalysis>());

        private static CallerRecoveryContext Context(
            int radius,
            IReadOnlyDictionary<Rva, FunctionMatchResult> matches,
            IReadOnlyDictionary<Rva, SymbolAnalysis> anchors,
            PeImage? previousImage = null,
            PeImage? currentImage = null) => new(
            radius,
            matches,
            anchors,
            previousImage ?? TestImages.WithExecutableBytes(new byte[0x4000]),
            currentImage ?? TestImages.WithExecutableBytes(new byte[0x4000]),
            new IcedInstructionDecoder());

        private static PeImage ImageWithDirectCall(uint callSite, uint target, bool hasFullWindow) {
            var bytes = new byte[0x4000];
            var offset = checked((int)(callSite - 0x1000));
            if (hasFullWindow)
                Array.Fill(bytes, (byte)0x90, offset - CallSiteFingerprint.InstructionRadius, CallSiteFingerprint.InstructionRadius);
            bytes[offset] = 0xE8;
            BitConverter.GetBytes(checked((int)(target - (callSite + 5)))).CopyTo(bytes, offset + 1);
            if (hasFullWindow)
                Array.Fill(bytes, (byte)0x90, offset + 5, CallSiteFingerprint.InstructionRadius);
            else
                bytes[offset + 5] = 0xC3;
            return TestImages.WithExecutableBytes(bytes);
        }

        private static PeImage ImageWithDirectJump(uint callSite, uint target) {
            var bytes = new byte[0x4000];
            var offset = checked((int)(callSite - 0x1000));
            Array.Fill(bytes, (byte)0x90, offset - CallSiteFingerprint.InstructionRadius, CallSiteFingerprint.InstructionRadius);
            bytes[offset] = 0xE9;
            BitConverter.GetBytes(checked((int)(target - (callSite + 5)))).CopyTo(bytes, offset + 1);
            Array.Fill(bytes, (byte)0x90, offset + 5, CallSiteFingerprint.InstructionRadius);
            return TestImages.WithExecutableBytes(bytes);
        }

        private static SymbolAnalysis Analysis(
            uint target,
            LocationKind kind,
            SymbolStatus status,
            SignatureScanResult previousScan,
            Rva? currentTarget = null) => new(
            "Test.Symbol",
            null,
            kind,
            SignatureDefinition.Parse("Test.Symbol", "E8 ?? ?? ?? ??", [1]),
            new Rva(target),
            previousScan,
            new SignatureScanResult([], false, []),
            status,
            currentTarget,
            [],
            null,
            []);

        private static FunctionMatchResult ExactMatch(uint target) => new(
            SymbolStatus.StructuralRecovered,
            new Rva(target),
            new FunctionFingerprint("exact", [], 0, 0),
            []);
    }

    private static class TestGraphs {
        public static CallGraph OldIncomingCall(uint caller, uint callSite, uint target) => Graph(
            Function(caller, [Instruction(caller, "Push", FlowControlKind.Next), Call(callSite, target), Instruction(callSite + 5, "Ret", FlowControlKind.Return)]),
            [new CallEdge(new Rva(caller), new Rva(callSite), new Rva(target), CallEdgeKind.DirectCall)]);

        public static CallGraph CurrentIncomingCall(uint caller, uint callSite, uint target) => Graph(
            Function(caller, [Instruction(caller, "Push", FlowControlKind.Next), Call(callSite, target), Instruction(callSite + 5, "Ret", FlowControlKind.Return)]),
            [new CallEdge(new Rva(caller), new Rva(callSite), new Rva(target), CallEdgeKind.DirectCall)]);

        public static CallGraph TwoOldCallersOf(uint target) => Graph(
            Function(0x1200, [Instruction(0x1200, "Push", FlowControlKind.Next), Call(0x1230, target), Instruction(0x1235, "Ret", FlowControlKind.Return)]),
            Function(0x1300, [Instruction(0x1300, "Push", FlowControlKind.Next), Call(0x1330, target), Instruction(0x1335, "Ret", FlowControlKind.Return)]),
            [new CallEdge(new Rva(0x1200), new Rva(0x1230), new Rva(target), CallEdgeKind.DirectCall),
             new CallEdge(new Rva(0x1300), new Rva(0x1330), new Rva(target), CallEdgeKind.DirectCall)]);

        public static CallGraph TwoMappedCurrentCallersOf(uint target) => Graph(
            Function(0x2200, [Instruction(0x2200, "Push", FlowControlKind.Next), Call(0x2230, target), Instruction(0x2235, "Ret", FlowControlKind.Return)]),
            Function(0x2300, [Instruction(0x2300, "Push", FlowControlKind.Next), Call(0x2330, target), Instruction(0x2335, "Ret", FlowControlKind.Return)]),
            [new CallEdge(new Rva(0x2200), new Rva(0x2230), new Rva(target), CallEdgeKind.DirectCall),
             new CallEdge(new Rva(0x2300), new Rva(0x2330), new Rva(target), CallEdgeKind.DirectCall)]);

        public static CallGraph MappedCurrentCallersOf(uint firstTarget, uint secondTarget) => Graph(
            Function(0x2200, [Instruction(0x2200, "Push", FlowControlKind.Next), Call(0x2230, firstTarget), Instruction(0x2235, "Ret", FlowControlKind.Return)]),
            Function(0x2300, [Instruction(0x2300, "Push", FlowControlKind.Next), Call(0x2330, secondTarget), Instruction(0x2335, "Ret", FlowControlKind.Return)]),
            [new CallEdge(new Rva(0x2200), new Rva(0x2230), new Rva(firstTarget), CallEdgeKind.DirectCall),
             new CallEdge(new Rva(0x2300), new Rva(0x2330), new Rva(secondTarget), CallEdgeKind.DirectCall)]);

        public static CallGraph DispatchBlockReachableOnlyFromTrustedCallSite(uint callSite) => Graph(
            Function(0x1200, [Instruction(0x1200, "Ret", FlowControlKind.Return)]),
            []);

        public static CallGraph UniqueEquivalentDispatchBlock(uint callSite, uint target) => Graph(
            Function(0x2200, [Instruction(0x2200, "Ret", FlowControlKind.Return)]),
            []);

        public static CallGraph IncomingCallWithImagePointer(uint caller, uint callSite, uint target, ulong pointer) => Graph(
            Function(caller, [ImagePointer(caller, pointer), Call(callSite, target), Instruction(callSite + 5, "Ret", FlowControlKind.Return)]),
            [new CallEdge(new Rva(caller), new Rva(callSite), new Rva(target), CallEdgeKind.DirectCall)]);

        public static CallGraph IncomingCallWithScalar(uint caller, uint callSite, uint target, byte scalar) => Graph(
            Function(caller, [Scalar(caller, scalar), Call(callSite, target), Instruction(callSite + 5, "Ret", FlowControlKind.Return)]),
            [new CallEdge(new Rva(caller), new Rva(callSite), new Rva(target), CallEdgeKind.DirectCall)]);

        private static CallGraph Graph(FunctionGraph function, ImmutableArray<CallEdge> edges) => new([function], edges);

        private static CallGraph Graph(FunctionGraph first, FunctionGraph second, ImmutableArray<CallEdge> edges) => new([first, second], edges);

        private static FunctionGraph Function(uint begin, DecodedInstruction[] instructions) => new(
            new RuntimeFunctionRange(new Rva(begin), new Rva(begin + 0x80), new Rva(begin + 0x100)),
            false,
            [.. instructions],
            []);

        private static DecodedInstruction Call(uint rva, uint target) => new(
            new Rva(rva),
            [0xE8, 0, 0, 0, 0],
            "Call_NearBranch",
            FlowControlKind.DirectCall,
            new Rva(target),
            null,
            [new DecodedConstant(new ByteRange(1, 4), EncodedConstantKind.BranchDisplacement, 0)]);

        private static DecodedInstruction ImagePointer(uint rva, ulong pointer) => new(
            new Rva(rva),
            [0x48, 0xB8, .. BitConverter.GetBytes(pointer)],
            "Mov_Register_Immediate",
            FlowControlKind.Next,
            null,
            null,
            [new DecodedConstant(new ByteRange(2, 8), EncodedConstantKind.Immediate, pointer)]);

        private static DecodedInstruction Scalar(uint rva, byte scalar) => new(
            new Rva(rva),
            [0x83, 0xF8, scalar],
            "Cmp_Register_Immediate",
            FlowControlKind.Next,
            null,
            null,
            [new DecodedConstant(new ByteRange(2, 1), EncodedConstantKind.Immediate, scalar)]);

        private static DecodedInstruction Instruction(uint rva, string opcodeKey, FlowControlKind flowControl) => new(
            new Rva(rva),
            [0x90],
            opcodeKey,
            flowControl,
            null,
            null,
            []);
    }
}
