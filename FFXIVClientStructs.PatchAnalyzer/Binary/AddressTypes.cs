namespace FFXIVClientStructs.PatchAnalyzer.Binary;

public readonly record struct Rva(uint Value) : IComparable<Rva> {
    /// <summary>Compares this RVA with <paramref name="other"/>.</summary>
    /// <param name="other">The RVA to compare.</param>
    /// <returns>A signed value indicating the relative order of the RVAs.</returns>
    public int CompareTo(Rva other) => Value.CompareTo(other.Value);
}

public readonly record struct PreferredVa(ulong Value);

public readonly record struct FileOffset(int Value);

public readonly record struct SourceSpan(int Start, int Length);
