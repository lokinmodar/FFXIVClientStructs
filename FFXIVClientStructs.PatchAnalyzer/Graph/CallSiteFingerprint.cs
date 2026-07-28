using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;
using FFXIVClientStructs.PatchAnalyzer.Binary;
using FFXIVClientStructs.PatchAnalyzer.Decoding;

namespace FFXIVClientStructs.PatchAnalyzer.Graph;

/// <summary>Describes a normalized identity for a direct call-site instruction window.</summary>
public sealed record CallSiteFingerprint(
    string Sha256,
    ImmutableArray<string> OpcodeKeys,
    int InstructionCount) {
    /// <summary>Defines the required count of decoded instructions on each side of a call-site.</summary>
    public const int InstructionRadius = 4;

    /// <summary>Creates a normalized fingerprint for <paramref name="instructions"/>.</summary>
    /// <param name="instructions">The reachable instruction window containing a direct call.</param>
    /// <param name="imageSize">The image size used to identify RVA-valued immediate pointers, or zero when unavailable.</param>
    /// <returns>A deterministic fingerprint for the supplied instruction window.</returns>
    public static CallSiteFingerprint Create(IEnumerable<DecodedInstruction> instructions, uint imageSize = 0) {
        ArgumentNullException.ThrowIfNull(instructions);

        var window = instructions.ToImmutableArray();
        var opcodeKeys = window.Select(instruction => instruction.OpcodeKey).ToImmutableArray();
        var canonical = string.Join("\n", window.Select(instruction =>
            $"{instruction.OpcodeKey}|{Convert.ToHexString(NormalizeBytes(instruction, imageSize))}"));
        return new CallSiteFingerprint(
            Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))),
            opcodeKeys,
            window.Length);
    }

    /// <summary>Creates a normalized fingerprint around a direct call within <paramref name="function"/>.</summary>
    /// <param name="function">The function that contains the direct call.</param>
    /// <param name="callSite">The RVA of the direct call instruction.</param>
    /// <param name="instructionRadius">The maximum count of reachable instructions on each side of the call.</param>
    /// <param name="imageSize">The image size used to identify RVA-valued immediate pointers, or zero when unavailable.</param>
    /// <returns>A deterministic fingerprint for the bounded call-site window.</returns>
    public static CallSiteFingerprint Create(FunctionGraph function, Rva callSite, int instructionRadius, uint imageSize = 0) {
        ArgumentNullException.ThrowIfNull(function);
        if (instructionRadius != InstructionRadius)
            throw new ArgumentOutOfRangeException(nameof(instructionRadius), instructionRadius, "The call-site instruction radius must be exactly four.");

        var instructions = function.Instructions.OrderBy(instruction => instruction.Rva.Value).ToImmutableArray();
        var callIndex = instructions
            .Select((instruction, index) => new { instruction, index })
            .Where(item => item.instruction.Rva == callSite)
            .Select(item => item.index)
            .DefaultIfEmpty(-1)
            .First();
        if (callIndex < 0)
            throw new ArgumentException("The call-site RVA is not a reachable instruction in the supplied function.", nameof(callSite));

        var start = Math.Max(0, callIndex - instructionRadius);
        var count = Math.Min(instructions.Length - start, instructionRadius * 2 + 1);
        return Create(instructions.Skip(start).Take(count), imageSize);
    }

    private static byte[] NormalizeBytes(DecodedInstruction instruction, uint imageSize) {
        var bytes = instruction.Bytes.ToArray();
        foreach (var constant in instruction.Constants) {
            if (constant.Kind is EncodedConstantKind.BranchDisplacement or EncodedConstantKind.IpRelativeDisplacement ||
                constant.Kind == EncodedConstantKind.Immediate && imageSize != 0 && constant.UnsignedValue < imageSize)
                ZeroRange(bytes, constant.Range);
        }

        return bytes;
    }

    private static void ZeroRange(byte[] bytes, ByteRange range) {
        if (range.Start < 0 || range.Length < 0 || range.Start > bytes.Length - range.Length)
            throw new ArgumentException("An encoded constant range is outside the instruction bytes.", nameof(range));

        Array.Clear(bytes, range.Start, range.Length);
    }
}
