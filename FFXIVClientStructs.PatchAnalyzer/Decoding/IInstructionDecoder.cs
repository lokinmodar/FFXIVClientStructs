using FFXIVClientStructs.PatchAnalyzer.Binary;

namespace FFXIVClientStructs.PatchAnalyzer.Decoding;

public interface IInstructionDecoder {
    DecodeResult Decode(ReadOnlySpan<byte> bytes, Rva instructionRva);
}
