using System.Collections.Immutable;
using FFXIVClientStructs.PatchAnalyzer.Analysis;
using FFXIVClientStructs.PatchAnalyzer.Binary;
using FFXIVClientStructs.PatchAnalyzer.Decoding;
using FFXIVClientStructs.PatchAnalyzer.Signatures;

namespace FFXIVClientStructs.PatchAnalyzer.Matching;

public sealed class SignatureSynthesizer {
    private const int MaximumPatternLength = 96;
    private const int MaximumValidationMatches = 2;
    private readonly FunctionIndex functionIndex;
    private readonly IInstructionDecoder decoder;

    public SignatureSynthesizer(FunctionIndex functionIndex, IInstructionDecoder decoder) {
        ArgumentNullException.ThrowIfNull(functionIndex);
        ArgumentNullException.ThrowIfNull(decoder);
        this.functionIndex = functionIndex;
        this.decoder = decoder;
    }

    public SignatureProposal? Synthesize(PeImage image, Rva recoveredTarget, Rva? recoveryCallSite) {
        ArgumentNullException.ThrowIfNull(image);

        var targetRange = functionIndex.FindContaining(recoveredTarget);
        if (targetRange is { } range && range.Begin == recoveredTarget) {
            var entryProposal = SynthesizeFrom(
                image,
                range,
                range.Begin,
                recoveredTarget,
                [],
                "FunctionEntry");
            if (entryProposal is not null)
                return entryProposal;
        }

        if (recoveryCallSite is not { } callSite || functionIndex.FindContaining(callSite) is not { } callSiteRange)
            return null;

        return SynthesizeFrom(
            image,
            callSiteRange,
            callSite,
            recoveredTarget,
            [1],
            "RecoveryCallSite",
            requireLeadingDirectCall: true);
    }

    private SignatureProposal? SynthesizeFrom(
        PeImage image,
        RuntimeFunctionRange range,
        Rva start,
        Rva recoveredTarget,
        ImmutableArray<ushort> relativeFollowOffsets,
        string source,
        bool requireLeadingDirectCall = false) {
        var bytes = new List<byte>();
        var mask = new List<bool>();
        var current = start;

        while (current.Value < range.End.Value && bytes.Count < MaximumPatternLength) {
            if (!TryDecode(image, range, current, out var instruction) ||
                bytes.Count + instruction.Bytes.Length > MaximumPatternLength)
                return null;
            if (requireLeadingDirectCall && bytes.Count == 0 && !IsDirectCallTo(instruction, recoveredTarget))
                return null;
            if (!TryAppendInstruction(image, instruction, bytes, mask))
                return null;

            var patternText = PatternText(bytes, mask);
            var definition = SignatureDefinition.Parse("SynthesizedProposal", patternText, relativeFollowOffsets);
            var scan = SignatureScanner.Scan(image, [definition], MaximumValidationMatches)[definition.GeneratedName];
            if (!scan.Truncated && scan.Matches.Length == 1 && scan.Matches[0].ResolvedRva == recoveredTarget) {
                return new SignatureProposal(
                    patternText,
                    relativeFollowOffsets,
                    start,
                    recoveredTarget,
                    bytes.Count,
                    source);
            }

            if (!FallsThrough(instruction))
                break;
            current = new Rva(checked(current.Value + (uint)instruction.Bytes.Length));
        }

        return null;
    }

    private bool TryDecode(PeImage image, RuntimeFunctionRange range, Rva rva, out DecodedInstruction instruction) {
        instruction = null!;
        if (!image.TryRead(rva, checked((int)(range.End.Value - rva.Value)), out var available))
            return false;

        var result = decoder.Decode(available.Span, rva);
        if (!result.Success || result.Instruction is not { } decoded || decoded.Rva != rva || decoded.Bytes.IsEmpty ||
            decoded.Bytes.Length > range.End.Value - rva.Value)
            return false;

        instruction = decoded;
        return true;
    }

    private static bool TryAppendInstruction(
        PeImage image,
        DecodedInstruction instruction,
        List<byte> bytes,
        List<bool> mask) {
        var instructionBytes = instruction.Bytes;
        bytes.AddRange(instructionBytes);
        for (var index = 0; index < instructionBytes.Length; index++)
            mask.Add(true);

        foreach (var constant in instruction.Constants) {
            if (!ShouldWildcard(image, constant))
                continue;
            if (constant.Range.Start < 0 || constant.Range.Length < 0 ||
                constant.Range.Start > instructionBytes.Length - constant.Range.Length)
                return false;

            var offset = bytes.Count - instructionBytes.Length + constant.Range.Start;
            for (var index = 0; index < constant.Range.Length; index++)
                mask[offset + index] = false;
        }

        return true;
    }

    private static bool ShouldWildcard(PeImage image, DecodedConstant constant) => constant.Kind switch {
        EncodedConstantKind.BranchDisplacement or EncodedConstantKind.IpRelativeDisplacement => true,
        EncodedConstantKind.Immediate => IsPreferredImageAddress(image, constant.UnsignedValue),
        _ => false
    };

    private static bool IsPreferredImageAddress(PeImage image, ulong value) {
        var imageEnd = checked(image.ImageBase + (ulong)image.SizeOfImage);
        return value >= image.ImageBase && value < imageEnd;
    }

    private static string PatternText(IReadOnlyList<byte> bytes, IReadOnlyList<bool> mask) => string.Join(" ",
        Enumerable.Range(0, bytes.Count).Select(index => mask[index] ? bytes[index].ToString("X2") : "??"));

    private static bool IsDirectCallTo(DecodedInstruction instruction, Rva target) =>
        instruction.Bytes[0] is 0xE8 or 0xE9 &&
        instruction.FlowControl is FlowControlKind.DirectCall or FlowControlKind.DirectBranch &&
        instruction.NearBranchTarget == target;

    private static bool FallsThrough(DecodedInstruction instruction) => instruction.FlowControl is not (
        FlowControlKind.DirectBranch or
        FlowControlKind.IndirectBranch or
        FlowControlKind.Return or
        FlowControlKind.Interrupt or
        FlowControlKind.Exception);
}
