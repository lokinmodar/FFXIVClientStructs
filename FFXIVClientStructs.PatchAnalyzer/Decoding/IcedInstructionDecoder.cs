using System.Collections.Immutable;
using FFXIVClientStructs.PatchAnalyzer.Binary;
using Iced.Intel;

namespace FFXIVClientStructs.PatchAnalyzer.Decoding;

public sealed class IcedInstructionDecoder : IInstructionDecoder {
    public DecodeResult Decode(ReadOnlySpan<byte> bytes, Rva instructionRva) {
        var decoder = Decoder.Create(64, new ByteArrayCodeReader(bytes.ToArray()));
        decoder.IP = instructionRva.Value;
        var instruction = decoder.Decode();

        if (instruction.Code == Code.INVALID)
            return Failure("The instruction encoding is invalid or truncated.");

        if (instruction.Length > bytes.Length)
            return Failure("The instruction is truncated.");

        var hasNearBranchTarget = Enumerable.Range(0, instruction.OpCount)
            .Select(instruction.GetOpKind)
            .Any(kind => kind.ToString().StartsWith("NearBranch", StringComparison.Ordinal));
        var hasIpRelativeTarget = instruction.IsIPRelativeMemoryOperand;

        Rva? nearBranchTarget = null;
        Rva? ipRelativeTarget = null;
        if (hasNearBranchTarget && !TryGetRva(instruction.NearBranchTarget, out nearBranchTarget)
            || hasIpRelativeTarget && !TryGetRva(instruction.IPRelativeMemoryAddress, out ipRelativeTarget))
            return Failure("The instruction target is outside the 32-bit RVA domain.");

        var constants = GetConstants(bytes[..instruction.Length], decoder.GetConstantOffsets(in instruction), hasNearBranchTarget, hasIpRelativeTarget);
        return new DecodeResult(
            true,
            new DecodedInstruction(
                instructionRva,
                bytes[..instruction.Length].ToArray().ToImmutableArray(),
                GetOpcodeKey(instruction),
                GetFlowControl(instruction.FlowControl),
                nearBranchTarget,
                ipRelativeTarget,
                constants),
            null);
    }

    private static DecodeResult Failure(string error) => new(false, null, error);

    private static bool TryGetRva(ulong target, out Rva? rva) {
        if (target > uint.MaxValue) {
            rva = null;
            return false;
        }

        rva = new Rva((uint)target);
        return true;
    }

    private static ImmutableArray<DecodedConstant> GetConstants(ReadOnlySpan<byte> bytes, ConstantOffsets offsets, bool hasNearBranchTarget, bool hasIpRelativeTarget) {
        var constants = ImmutableArray.CreateBuilder<DecodedConstant>();

        AddConstant(constants, bytes, offsets.DisplacementOffset, offsets.DisplacementSize,
            hasNearBranchTarget ? EncodedConstantKind.BranchDisplacement : hasIpRelativeTarget ? EncodedConstantKind.IpRelativeDisplacement : EncodedConstantKind.Displacement);
        AddConstant(constants, bytes, offsets.ImmediateOffset, offsets.ImmediateSize,
            hasNearBranchTarget ? EncodedConstantKind.BranchDisplacement : EncodedConstantKind.Immediate);
        AddConstant(constants, bytes, offsets.ImmediateOffset2, offsets.ImmediateSize2, EncodedConstantKind.Immediate);
        return constants.ToImmutable();
    }

    private static void AddConstant(ImmutableArray<DecodedConstant>.Builder constants, ReadOnlySpan<byte> bytes, int offset, int size, EncodedConstantKind kind) {
        if (size != 0)
            constants.Add(new DecodedConstant(new ByteRange(offset, size), kind, ReadUnsignedValue(bytes, offset, size)));
    }

    private static ulong ReadUnsignedValue(ReadOnlySpan<byte> bytes, int offset, int size) {
        var value = 0UL;
        for (var index = 0; index < size; index++)
            value |= (ulong)bytes[offset + index] << (index * 8);
        return value;
    }

    private static string GetOpcodeKey(Instruction instruction) {
        var operands = Enumerable.Range(0, instruction.OpCount)
            .Select(index => GetOperandKindName(instruction.GetOpKind(index)));
        return string.Join("_", [instruction.Mnemonic.ToString(), .. operands]);
    }

    private static string GetOperandKindName(OpKind kind) => kind switch {
        OpKind.Register => "Register",
        _ when kind.ToString().StartsWith("NearBranch", StringComparison.Ordinal) => "NearBranch",
        _ when kind.ToString().StartsWith("FarBranch", StringComparison.Ordinal) => "FarBranch",
        _ when kind.ToString().StartsWith("Immediate", StringComparison.Ordinal) => "Immediate",
        _ when kind.ToString().StartsWith("Memory", StringComparison.Ordinal) => "Memory",
        _ => "Other"
    };

    private static FlowControlKind GetFlowControl(FlowControl flowControl) => flowControl switch {
        FlowControl.Next => FlowControlKind.Next,
        FlowControl.Call => FlowControlKind.DirectCall,
        FlowControl.IndirectCall => FlowControlKind.IndirectCall,
        FlowControl.ConditionalBranch => FlowControlKind.ConditionalBranch,
        FlowControl.UnconditionalBranch => FlowControlKind.DirectBranch,
        FlowControl.IndirectBranch => FlowControlKind.IndirectBranch,
        FlowControl.Return => FlowControlKind.Return,
        FlowControl.Interrupt => FlowControlKind.Interrupt,
        FlowControl.Exception => FlowControlKind.Exception,
        FlowControl.XbeginXabortXend => FlowControlKind.Transactional,
        _ => throw new ArgumentOutOfRangeException(nameof(flowControl), flowControl, null)
    };
}
