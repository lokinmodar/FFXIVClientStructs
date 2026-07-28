using System.Buffers.Binary;
using System.Collections.Immutable;
using FFXIVClientStructs.PatchAnalyzer.Binary;

namespace FFXIVClientStructs.PatchAnalyzer.Signatures;

public sealed record SignatureMatch(Rva PatternRva, Rva ResolvedRva);

public sealed record SignatureScanResult(
    ImmutableArray<SignatureMatch> Matches,
    bool Truncated,
    ImmutableArray<string> Diagnostics);

public static class SignatureScanner {
    public static ImmutableSortedDictionary<string, SignatureScanResult> Scan(
        PeImage image,
        IReadOnlyList<SignatureDefinition> definitions,
        int maxMatches) {
        ArgumentNullException.ThrowIfNull(image);
        ArgumentNullException.ThrowIfNull(definitions);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxMatches);

        var states = definitions.ToDictionary(definition => definition.GeneratedName, definition => new ScanState(definition));
        if (states.Count != definitions.Count)
            throw new ArgumentException("Signature definitions must have unique generated names.", nameof(definitions));

        var anchoredDefinitions = states.Values
            .Select(state => new AnchoredDefinition(state, FindAnchor(state.Definition.Pattern)))
            .GroupBy(item => item.Anchor.Byte)
            .ToDictionary(group => group.Key, group => group.ToArray());

        foreach (var section in image.ExecutableSections) {
            var bytes = section.Bytes.Span;
            for (var index = 0; index < bytes.Length; index++) {
                if (!anchoredDefinitions.TryGetValue(bytes[index], out var candidates))
                    continue;

                foreach (var candidate in candidates) {
                    var start = index - candidate.Anchor.Offset;
                    if (start < 0 || !Matches(section, start, candidate.State.Definition.Pattern))
                        continue;

                    var patternRva = new Rva(checked(section.Rva.Value + (uint)start));
                    if (!TryResolve(image, candidate.State.Definition, patternRva, out var resolvedRva, out var diagnostic)) {
                        candidate.State.Diagnostics.Add(diagnostic!);
                        continue;
                    }

                    if (candidate.State.Matches.Count < maxMatches)
                        candidate.State.Matches.Add(new SignatureMatch(patternRva, resolvedRva));
                    else
                        candidate.State.Truncated = true;
                }
            }
        }

        return states.Values
            .OrderBy(state => state.Definition.GeneratedName, StringComparer.Ordinal)
            .ToImmutableSortedDictionary(
                state => state.Definition.GeneratedName,
                state => new SignatureScanResult(
                    state.Matches.OrderBy(match => match.PatternRva.Value).ToImmutableArray(),
                    state.Truncated,
                    state.Diagnostics.ToImmutableArray()),
                StringComparer.Ordinal);
    }

    private static Anchor FindAnchor(SignaturePattern pattern) {
        for (var index = 0; index < pattern.Mask.Length; index++) {
            if (pattern.Mask[index] != 0)
                return new Anchor(pattern.Bytes[index], index);
        }

        throw new ArgumentException("A signature pattern must contain at least one non-wildcard byte.", nameof(pattern));
    }

    private static bool Matches(PeSection section, int start, SignaturePattern pattern) {
        var bytes = section.Bytes.Span;
        if (start > bytes.Length - pattern.Bytes.Length)
            return false;

        for (var index = 0; index < pattern.Bytes.Length; index++) {
            if (pattern.Mask[index] != 0 && bytes[start + index] != pattern.Bytes[index])
                return false;
        }

        return true;
    }

    private static bool TryResolve(
        PeImage image,
        SignatureDefinition definition,
        Rva patternRva,
        out Rva resolvedRva,
        out string? diagnostic) {
        resolvedRva = patternRva;
        diagnostic = null;

        foreach (var offset in definition.RelativeFollowOffsets) {
            if (!TryAdd(resolvedRva.Value, offset, out var displacementRva) || !image.TryRead(new Rva(displacementRva), sizeof(int), out var displacementBytes)) {
                diagnostic = $"Dropped match at 0x{patternRva.Value:X}: rel32 displacement is outside a section.";
                return false;
            }

            var displacement = BinaryPrimitives.ReadInt32LittleEndian(displacementBytes.Span);
            var nextInstruction = (long)displacementRva + sizeof(int);
            var target = nextInstruction + displacement;
            if (target < 0 || target >= image.SizeOfImage || target > uint.MaxValue || !image.TryRead(new Rva((uint)target), 1, out _)) {
                diagnostic = $"Dropped match at 0x{patternRva.Value:X}: rel32 target is out of image bounds.";
                return false;
            }

            resolvedRva = new Rva((uint)target);
        }

        return true;
    }

    private static bool TryAdd(uint value, ushort offset, out uint result) {
        var sum = (ulong)value + offset;
        result = (uint)sum;
        return sum <= uint.MaxValue;
    }

    private sealed class ScanState(SignatureDefinition definition) {
        public SignatureDefinition Definition { get; } = definition;
        public List<SignatureMatch> Matches { get; } = [];
        public List<string> Diagnostics { get; } = [];
        public bool Truncated { get; set; }
    }

    private sealed record AnchoredDefinition(ScanState State, Anchor Anchor);
    private readonly record struct Anchor(byte Byte, int Offset);
}
