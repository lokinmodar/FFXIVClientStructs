using System.Reflection.PortableExecutable;

namespace FFXIVClientStructs.PatchAnalyzer.Binary;

public sealed record PeSection(
    string Name,
    Rva Rva,
    int VirtualSize,
    FileOffset FileOffset,
    ReadOnlyMemory<byte> Bytes,
    SectionCharacteristics Characteristics);
