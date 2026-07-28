namespace FFXIVClientStructs.PatchAnalyzer.Binary;

public sealed record BinaryIdentity(
    string FileName,
    long Length,
    string Sha256,
    string? GameVersion,
    string VersionSource);
