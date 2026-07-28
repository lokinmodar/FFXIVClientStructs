using System.Collections.Immutable;
using FFXIVClientStructs.PatchAnalyzer.Binary;
using FFXIVClientStructs.PatchAnalyzer.Decoding;

namespace FFXIVClientStructs.PatchAnalyzer.Tests.Fixtures;

public sealed record FakeInstructionSpec(Rva Rva, DecodeResult Result);

public sealed class FakeInstructionDecoder : IInstructionDecoder {
    private readonly IReadOnlyDictionary<Rva, DecodeResult> results;

    private FakeInstructionDecoder(IReadOnlyDictionary<Rva, DecodeResult> results) => this.results = results;

    public static FakeInstructionDecoder For(IEnumerable<FakeInstructionSpec> instructions) =>
        new(instructions.ToDictionary(instruction => instruction.Rva, instruction => instruction.Result));

    public DecodeResult Decode(ReadOnlySpan<byte> bytes, Rva instructionRva) =>
        results.TryGetValue(instructionRva, out var result)
            ? result
            : new DecodeResult(false, null, $"No fake instruction is registered at RVA 0x{instructionRva.Value:X8}.");
}
