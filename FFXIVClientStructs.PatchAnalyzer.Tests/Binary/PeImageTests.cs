using System.Buffers.Binary;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using FFXIVClientStructs.PatchAnalyzer.Binary;
using FFXIVClientStructs.PatchAnalyzer.Tests.Fixtures;
using Xunit;

namespace FFXIVClientStructs.PatchAnalyzer.Tests.Binary;

public class PeImageTests {
    [Fact]
    public void Open_Amd64Pe32Plus_ExposesIdentitySectionsAndConversions() {
        using var fixture = SyntheticPeBuilder.Create()
            .WithImageBase(0x140000000)
            .WithSection(".text", 0x1000, [0x90, 0xC3], executable: true)
            .WithSection(".rdata", 0x2000, [0x01], executable: false)
            .WithAdjacentVersion("2026.06.18.0000.0000")
            .Write();

        var image = PeImage.Open(fixture.ExecutablePath);

        Assert.Equal(0x140000000UL, image.ImageBase);
        Assert.Equal("2026.06.18.0000.0000", image.Identity.GameVersion);
        Assert.Equal("ffxiv_dx11.exe", image.Identity.FileName);
        Assert.DoesNotContain(fixture.DirectoryPath, image.Identity.FileName, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(fixture.ExecutablePath))), image.Identity.Sha256);
        Assert.Equal(2, image.Sections.Length);
        Assert.Single(image.ExecutableSections);
        Assert.Equal(".text", image.ExecutableSections[0].Name);
        Assert.True(image.TryRead(new Rva(0x1000), 2, out var bytes));
        Assert.Equal(new byte[] { 0x90, 0xC3 }, bytes.ToArray());
        Assert.Equal(new PreferredVa(0x140001000), image.ToPreferredVa(new Rva(0x1000)));
        Assert.True(image.TryToRva(new PreferredVa(0x140001000), out var rva));
        Assert.Equal(new Rva(0x1000), rva);
    }

    [Fact]
    public void Open_AdjacentVersionAbsent_UsesNoVersionSource() {
        using var fixture = SyntheticPeBuilder.Create()
            .WithSection(".text", 0x1000, [0x90], executable: true)
            .Write();

        var image = PeImage.Open(fixture.ExecutablePath);

        Assert.Null(image.Identity.GameVersion);
        Assert.Equal("none", image.Identity.VersionSource);
    }

    [Theory]
    [InlineData(Machine.I386, PEMagic.PE32Plus)]
    [InlineData(Machine.Amd64, PEMagic.PE32)]
    public void Open_IncompatibleImage_Throws(Machine machine, PEMagic magic) {
        using var fixture = SyntheticPeBuilder.Create().WithHeaders(machine, magic).Write();

        Assert.Throws<InvalidDataException>(() => PeImage.Open(fixture.ExecutablePath));
    }

    [Fact]
    public void TryRead_RangeCrossingSectionBoundary_ReturnsFalse() {
        using var fixture = SyntheticPeBuilder.Create()
            .WithSection(".text", 0x1000, [0x90], executable: true)
            .WithSection(".rdata", 0x2000, [0x01], executable: false)
            .Write();

        var image = PeImage.Open(fixture.ExecutablePath);

        Assert.False(image.TryRead(new Rva(0x1000), 2, out _));
        Assert.False(image.TryRead(new Rva(0x0FFF), 1, out _));
        Assert.False(image.TryRead(new Rva(0x1000), -1, out _));
    }

    [Fact]
    public void Open_OverlappingSectionRanges_Throws() {
        using var fixture = SyntheticPeBuilder.Create()
            .WithSection(".text", 0x1000, [0x90], executable: true)
            .WithSection(".rdata", 0x1000, [0x01], executable: false)
            .Write();

        Assert.Throws<InvalidDataException>(() => PeImage.Open(fixture.ExecutablePath));
    }

    [Theory]
    [InlineData(8, 0)]
    [InlineData(20, 0x7FFFFFFF)]
    public void Open_InvalidSectionFileRange_Throws(int fieldOffset, int value) {
        using var fixture = SyntheticPeBuilder.Create()
            .WithSection(".text", 0x1000, [0x90], executable: true)
            .Write();
        var executable = File.ReadAllBytes(fixture.ExecutablePath);
        BinaryPrimitives.WriteInt32LittleEndian(executable.AsSpan(0x188 + fieldOffset), value);
        File.WriteAllBytes(fixture.ExecutablePath, executable);

        Assert.Throws<InvalidDataException>(() => PeImage.Open(fixture.ExecutablePath));
    }

    [Fact]
    public void TestImages_WithExecutableBytes_RemainsReadableAfterFixtureDeletion() {
        var image = TestImages.WithExecutableBytes([0x90, 0xC3]);

        Assert.True(image.TryRead(new Rva(0x1000), 2, out var bytes));
        Assert.Equal(new byte[] { 0x90, 0xC3 }, bytes.ToArray());
    }
}
