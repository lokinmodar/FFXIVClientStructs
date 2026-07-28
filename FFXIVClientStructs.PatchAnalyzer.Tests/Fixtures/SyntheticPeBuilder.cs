using System.Buffers.Binary;
using System.Reflection.PortableExecutable;

namespace FFXIVClientStructs.PatchAnalyzer.Tests.Fixtures;

public sealed class SyntheticPeBuilder {
    private const int FileAlignment = 0x200;
    private const int SectionAlignment = 0x1000;
    private readonly List<SectionDefinition> sections = [];
    private Machine machine = Machine.Amd64;
    private PEMagic magic = PEMagic.PE32Plus;
    private ulong imageBase = 0x140000000;
    private uint exceptionDirectoryRva;
    private int exceptionDirectorySize;
    private string? adjacentVersion;

    public static SyntheticPeBuilder Create() => new();

    public SyntheticPeBuilder WithHeaders(Machine machine, PEMagic magic) {
        this.machine = machine;
        this.magic = magic;
        return this;
    }

    public SyntheticPeBuilder WithImageBase(ulong imageBase) {
        this.imageBase = imageBase;
        return this;
    }

    public SyntheticPeBuilder WithSection(string name, uint rva, byte[] bytes, bool executable) {
        sections.Add(new SectionDefinition(name, rva, bytes, executable));
        return this;
    }

    public SyntheticPeBuilder WithExceptionDirectory(uint rva, int size) {
        exceptionDirectoryRva = rva;
        exceptionDirectorySize = size;
        return this;
    }

    public SyntheticPeBuilder WithAdjacentVersion(string version) {
        adjacentVersion = version;
        return this;
    }

    public SyntheticPeFixture Write() {
        var directoryPath = Path.Combine(Path.GetTempPath(), $"FFXIVClientStructs.PatchAnalyzer.Tests.{Guid.NewGuid():N}");
        Directory.CreateDirectory(directoryPath);

        var executablePath = Path.Combine(directoryPath, "ffxiv_dx11.exe");
        var sectionTableOffset = 0x80 + 4 + 20 + 0xF0;
        var headersSize = Align(sectionTableOffset + sections.Count * 40, FileAlignment);
        var nextFileOffset = headersSize;
        var layouts = new List<SectionLayout>(sections.Count);

        foreach (var section in sections) {
            layouts.Add(new SectionLayout(section, nextFileOffset));
            nextFileOffset += Align(section.Bytes.Length, FileAlignment);
        }

        var file = new byte[nextFileOffset];
        var span = file.AsSpan();
        span[0] = (byte)'M';
        span[1] = (byte)'Z';
        BinaryPrimitives.WriteInt32LittleEndian(span[0x3C..], 0x80);
        span[0x80] = (byte)'P';
        span[0x81] = (byte)'E';
        BinaryPrimitives.WriteUInt16LittleEndian(span[0x84..], (ushort)machine);
        BinaryPrimitives.WriteUInt16LittleEndian(span[0x86..], (ushort)sections.Count);
        BinaryPrimitives.WriteUInt16LittleEndian(span[0x94..], 0xF0);
        BinaryPrimitives.WriteUInt16LittleEndian(span[0x98..], (ushort)magic);
        BinaryPrimitives.WriteUInt32LittleEndian(span[0xB8..], SectionAlignment);
        BinaryPrimitives.WriteUInt32LittleEndian(span[0xBC..], FileAlignment);
        BinaryPrimitives.WriteUInt64LittleEndian(span[0xB0..], imageBase);
        BinaryPrimitives.WriteUInt32LittleEndian(span[0xD0..], (uint)Align((int)GetImageEnd(), SectionAlignment));
        BinaryPrimitives.WriteUInt32LittleEndian(span[0xD4..], (uint)headersSize);
        BinaryPrimitives.WriteUInt32LittleEndian(span[0xF4..], 16);
        BinaryPrimitives.WriteUInt32LittleEndian(span[0x120..], exceptionDirectoryRva);
        BinaryPrimitives.WriteUInt32LittleEndian(span[0x124..], (uint)exceptionDirectorySize);

        for (var index = 0; index < layouts.Count; index++) {
            var layout = layouts[index];
            var sectionHeader = sectionTableOffset + index * 40;
            var nameBytes = System.Text.Encoding.ASCII.GetBytes(layout.Definition.Name);
            nameBytes.AsSpan(0, Math.Min(nameBytes.Length, 8)).CopyTo(span[sectionHeader..]);
            BinaryPrimitives.WriteUInt32LittleEndian(span[(sectionHeader + 8)..], (uint)layout.Definition.Bytes.Length);
            BinaryPrimitives.WriteUInt32LittleEndian(span[(sectionHeader + 12)..], layout.Definition.Rva);
            BinaryPrimitives.WriteUInt32LittleEndian(span[(sectionHeader + 16)..], (uint)Align(layout.Definition.Bytes.Length, FileAlignment));
            BinaryPrimitives.WriteUInt32LittleEndian(span[(sectionHeader + 20)..], (uint)layout.FileOffset);
            BinaryPrimitives.WriteUInt32LittleEndian(span[(sectionHeader + 36)..], layout.Definition.Executable ? 0x60000020u : 0x40000040u);
            layout.Definition.Bytes.CopyTo(span[layout.FileOffset..]);
        }

        File.WriteAllBytes(executablePath, file);
        if (adjacentVersion is not null)
            File.WriteAllText(Path.Combine(directoryPath, "ffxivgame.ver"), adjacentVersion);

        return new SyntheticPeFixture(directoryPath, executablePath);
    }

    private uint GetImageEnd() => sections.Count == 0 ? (uint)SectionAlignment : sections.Max(section => section.Rva + (uint)section.Bytes.Length);

    private static int Align(int value, int alignment) => (value + alignment - 1) / alignment * alignment;

    private sealed record SectionDefinition(string Name, uint Rva, byte[] Bytes, bool Executable);
    private sealed record SectionLayout(SectionDefinition Definition, int FileOffset);
}

public sealed class SyntheticPeFixture(string directoryPath, string executablePath) : IDisposable {
    public string DirectoryPath { get; } = directoryPath;
    public string ExecutablePath { get; } = executablePath;

    public void Dispose() {
        if (Directory.Exists(DirectoryPath))
            Directory.Delete(DirectoryPath, recursive: true);
    }
}
