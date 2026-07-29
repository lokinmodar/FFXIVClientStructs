using System.Buffers.Binary;
using System.Collections.Immutable;

namespace FFXIVClientStructs.PatchAnalyzer.Binary;

public sealed record RuntimeFunctionRange(Rva Begin, Rva End, Rva UnwindInfo);

public sealed class FunctionIndex {
    private const int RuntimeFunctionSize = 12;

    private FunctionIndex(ImmutableArray<RuntimeFunctionRange> ranges) => Ranges = ranges;

    public ImmutableArray<RuntimeFunctionRange> Ranges { get; }

    public static FunctionIndex Build(PeImage image) {
        if (image.ExceptionDirectorySize == 0)
            return new FunctionIndex([]);

        if (image.ExceptionDirectorySize % RuntimeFunctionSize != 0)
            throw new InvalidDataException("The exception directory size is not divisible by the runtime-function record size.");

        if (!image.TryRead(image.ExceptionDirectoryRva, image.ExceptionDirectorySize, out var directory))
            throw new InvalidDataException("The exception directory is outside the image sections.");

        var ranges = new RuntimeFunctionRange[image.ExceptionDirectorySize / RuntimeFunctionSize];
        var bytes = directory.Span;
        for (var index = 0; index < ranges.Length; index++) {
            var record = bytes.Slice(index * RuntimeFunctionSize, RuntimeFunctionSize);
            var range = new RuntimeFunctionRange(
                new Rva(BinaryPrimitives.ReadUInt32LittleEndian(record)),
                new Rva(BinaryPrimitives.ReadUInt32LittleEndian(record[4..])),
                new Rva(BinaryPrimitives.ReadUInt32LittleEndian(record[8..])));

            if (range.Begin.Value >= range.End.Value)
                throw new InvalidDataException("A runtime-function range has an invalid extent.");
            if (!IsWithinExecutableSection(image, range))
                throw new InvalidDataException("A runtime-function range is outside an executable section.");

            ranges[index] = range;
        }

        Array.Sort(ranges, static (left, right) => left.Begin.Value.CompareTo(right.Begin.Value));
        for (var index = 1; index < ranges.Length; index++) {
            if (ranges[index].Begin.Value < ranges[index - 1].End.Value)
                throw new InvalidDataException("Runtime-function ranges overlap.");
        }

        return new FunctionIndex([.. ranges]);
    }

    public RuntimeFunctionRange? FindByStart(Rva start) {
        var index = FindFirstRangeAfter(start);
        return index < Ranges.Length && Ranges[index].Begin == start ? Ranges[index] : null;
    }

    public RuntimeFunctionRange? FindContaining(Rva rva) {
        var index = FindFirstRangeAfter(rva);
        if (index < Ranges.Length && Ranges[index].Begin == rva)
            return Ranges[index];
        if (index == 0)
            return null;

        var range = Ranges[index - 1];
        return rva.Value < range.End.Value ? range : null;
    }

    private static bool IsWithinExecutableSection(PeImage image, RuntimeFunctionRange range) {
        foreach (var section in image.ExecutableSections) {
            var sectionEnd = (ulong)section.Rva.Value + (uint)section.VirtualSize;
            if (range.Begin.Value >= section.Rva.Value && range.End.Value <= sectionEnd)
                return true;
        }

        return false;
    }

    private int FindFirstRangeAfter(Rva rva) {
        var low = 0;
        var high = Ranges.Length;
        while (low < high) {
            var middle = low + (high - low) / 2;
            if (Ranges[middle].Begin.Value < rva.Value)
                low = middle + 1;
            else
                high = middle;
        }

        return low;
    }
}
