namespace FFXIVClientStructs.PatchAnalyzer.Binary;

public readonly record struct Rva(uint Value);

public readonly record struct PreferredVa(ulong Value);

public readonly record struct FileOffset(int Value);

public readonly record struct SourceSpan(int Start, int Length);
