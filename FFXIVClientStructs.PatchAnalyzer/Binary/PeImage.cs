using System.Collections.Immutable;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;

namespace FFXIVClientStructs.PatchAnalyzer.Binary;

public sealed class PeImage {
    private readonly ImmutableArray<PeSection> sections;

    private PeImage(
        BinaryIdentity identity,
        ulong imageBase,
        int sizeOfImage,
        Rva exceptionDirectoryRva,
        int exceptionDirectorySize,
        ImmutableArray<PeSection> sections) {
        Identity = identity;
        ImageBase = imageBase;
        SizeOfImage = sizeOfImage;
        ExceptionDirectoryRva = exceptionDirectoryRva;
        ExceptionDirectorySize = exceptionDirectorySize;
        this.sections = sections;
        Sections = sections;
        ExecutableSections = sections.Where(section => (section.Characteristics & SectionCharacteristics.MemExecute) != 0).ToImmutableArray();
    }

    public BinaryIdentity Identity { get; }
    public ulong ImageBase { get; }
    public int SizeOfImage { get; }
    public Rva ExceptionDirectoryRva { get; }
    public int ExceptionDirectorySize { get; }
    public ImmutableArray<PeSection> Sections { get; }
    public ImmutableArray<PeSection> ExecutableSections { get; }

    public static PeImage Open(string path) {
        var fileBytes = File.ReadAllBytes(path);
        var identity = CreateIdentity(path, fileBytes);

        try {
            using var stream = new MemoryStream(fileBytes, writable: false);
            using var reader = new PEReader(stream, PEStreamOptions.LeaveOpen);
            var headers = reader.PEHeaders;
            var peHeader = headers.PEHeader;

            if (headers.CoffHeader.Machine != Machine.Amd64 || peHeader is null || peHeader.Magic != PEMagic.PE32Plus)
                throw new InvalidDataException("The image must be an AMD64 PE32+ executable.");

            var parsedSections = ParseSections(headers.SectionHeaders, fileBytes);
            var exceptionDirectory = peHeader.ExceptionTableDirectory;
            return new PeImage(
                identity,
                checked((ulong)peHeader.ImageBase),
                peHeader.SizeOfImage,
                new Rva((uint)exceptionDirectory.RelativeVirtualAddress),
                exceptionDirectory.Size,
                parsedSections);
        } catch (BadImageFormatException exception) {
            throw new InvalidDataException("The file is not a valid PE image.", exception);
        }
    }

    public bool TryRead(Rva rva, int length, out ReadOnlyMemory<byte> bytes) {
        bytes = default;
        if (length < 0)
            return false;

        foreach (var section in sections) {
            if (rva.Value < section.Rva.Value)
                continue;

            var offset = (ulong)rva.Value - section.Rva.Value;
            if (offset > (ulong)section.Bytes.Length || (ulong)length > (ulong)section.Bytes.Length - offset)
                continue;

            bytes = section.Bytes.Slice((int)offset, length);
            return true;
        }

        return false;
    }

    public PreferredVa ToPreferredVa(Rva rva) => new(checked(ImageBase + rva.Value));

    public bool TryToRva(PreferredVa preferredVa, out Rva rva) {
        rva = default;
        if (preferredVa.Value < ImageBase)
            return false;

        var value = preferredVa.Value - ImageBase;
        if (value > uint.MaxValue)
            return false;

        rva = new Rva((uint)value);
        return true;
    }

    private static BinaryIdentity CreateIdentity(string path, byte[] fileBytes) {
        var versionPath = Path.Combine(Path.GetDirectoryName(Path.GetFullPath(path))!, "ffxivgame.ver");
        var gameVersion = File.Exists(versionPath) ? File.ReadAllText(versionPath).Trim() : null;
        return new BinaryIdentity(
            Path.GetFileName(path),
            fileBytes.LongLength,
            Convert.ToHexString(SHA256.HashData(fileBytes)),
            gameVersion,
            gameVersion is null ? "none" : "ffxivgame.ver");
    }

    private static ImmutableArray<PeSection> ParseSections(IReadOnlyList<SectionHeader> sectionHeaders, byte[] fileBytes) {
        if (sectionHeaders.Count == 0)
            throw new InvalidDataException("The image does not contain any sections.");

        var sections = new List<PeSection>(sectionHeaders.Count);
        foreach (var header in sectionHeaders) {
            if (header.VirtualAddress <= 0 || header.VirtualSize <= 0 || header.SizeOfRawData <= 0 || header.PointerToRawData <= 0)
                throw new InvalidDataException("The image contains a section with a missing range.");

            var rawStart = header.PointerToRawData;
            var rawEnd = (long)rawStart + header.SizeOfRawData;
            var rvaEnd = (long)header.VirtualAddress + Math.Max(header.VirtualSize, header.SizeOfRawData);
            if (rawEnd > fileBytes.Length)
                throw new InvalidDataException("The image contains a section outside the file.");

            if (rvaEnd > uint.MaxValue || sections.Any(section => RangesOverlap(header.VirtualAddress, rvaEnd, section.Rva.Value, (long)section.Rva.Value + Math.Max(section.VirtualSize, section.Bytes.Length))))
                throw new InvalidDataException("The image contains overlapping sections.");

            var bytes = new byte[Math.Min(header.VirtualSize, header.SizeOfRawData)];
            Array.Copy(fileBytes, rawStart, bytes, 0, bytes.Length);
            sections.Add(new PeSection(
                header.Name,
                new Rva((uint)header.VirtualAddress),
                header.VirtualSize,
                new FileOffset(rawStart),
                bytes,
                header.SectionCharacteristics));
        }

        return sections.ToImmutableArray();
    }

    private static bool RangesOverlap(long start, long end, long otherStart, long otherEnd) => start < otherEnd && otherStart < end;
}
