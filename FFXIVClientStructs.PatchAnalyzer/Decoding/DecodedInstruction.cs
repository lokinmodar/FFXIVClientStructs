using System.Collections.Immutable;
using FFXIVClientStructs.PatchAnalyzer.Binary;

namespace FFXIVClientStructs.PatchAnalyzer.Decoding;

public enum FlowControlKind {
    Next, DirectCall, IndirectCall, ConditionalBranch, DirectBranch,
    IndirectBranch, Return, Interrupt, Exception, Transactional
}

public enum EncodedConstantKind {
    BranchDisplacement, IpRelativeDisplacement, Displacement, Immediate
}

public readonly record struct ByteRange(int Start, int Length);

public sealed record DecodedConstant(
    ByteRange Range,
    EncodedConstantKind Kind,
    ulong UnsignedValue);

public sealed record DecodedInstruction(
    Rva Rva,
    ImmutableArray<byte> Bytes,
    string OpcodeKey,
    FlowControlKind FlowControl,
    Rva? NearBranchTarget,
    Rva? IpRelativeTarget,
    ImmutableArray<DecodedConstant> Constants);

public sealed record DecodeResult(
    bool Success,
    DecodedInstruction? Instruction,
    string? Error);
