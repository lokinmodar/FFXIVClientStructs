using FFXIVClientStructs.PatchAnalyzer.Binary;
using FFXIVClientStructs.PatchAnalyzer.Tests.Fixtures;
using Xunit;

namespace FFXIVClientStructs.PatchAnalyzer.Tests.Binary;

public class FunctionIndexTests {
    [Fact]
    public void Build_UsesExceptionDirectoryAndFindsContainingRange() {
        using var fixture = SyntheticPeBuilder.Create()
            .WithSection(".text", 0x1000, new byte[0x80], executable: true)
            .WithRuntimeFunctions(
                new RuntimeFunctionSpec(0x1010, 0x1030, 0x3000),
                new RuntimeFunctionSpec(0x1040, 0x1060, 0x3010))
            .Write();
        var image = PeImage.Open(fixture.ExecutablePath);

        var index = FunctionIndex.Build(image);

        Assert.Equal(new Rva(0x1010), index.FindContaining(new Rva(0x1010))!.Begin);
        Assert.Equal(new Rva(0x1010), index.FindContaining(new Rva(0x1020))!.Begin);
        Assert.Null(index.FindContaining(new Rva(0x1030)));
    }

    [Fact]
    public void Build_SortsRangesAndFindsByStart() {
        using var fixture = SyntheticPeBuilder.Create()
            .WithSection(".text", 0x1000, new byte[0x80], executable: true)
            .WithRuntimeFunctions(
                new RuntimeFunctionSpec(0x1040, 0x1060, 0x3010),
                new RuntimeFunctionSpec(0x1010, 0x1030, 0x3000))
            .Write();

        var index = FunctionIndex.Build(PeImage.Open(fixture.ExecutablePath));

        Assert.Equal([new Rva(0x1010), new Rva(0x1040)], index.Ranges.Select(range => range.Begin));
        Assert.Equal(new Rva(0x1060), index.FindByStart(new Rva(0x1040))!.End);
        Assert.Null(index.FindByStart(new Rva(0x1020)));
    }

    [Fact]
    public void Build_WithoutExceptionDirectory_ReturnsEmptyIndex() {
        var image = TestImages.WithExecutableBytes(new byte[0x20]);

        var index = FunctionIndex.Build(image);

        Assert.Empty(index.Ranges);
        Assert.Null(index.FindContaining(new Rva(0x1000)));
    }

    [Theory]
    [InlineData(0x1010, 0x1010)]
    [InlineData(0x1020, 0x1010)]
    public void Build_InvalidRange_Throws(uint beginRva, uint endRva) {
        using var fixture = SyntheticPeBuilder.Create()
            .WithSection(".text", 0x1000, new byte[0x80], executable: true)
            .WithRuntimeFunctions(new RuntimeFunctionSpec(beginRva, endRva, 0x3000))
            .Write();

        Assert.Throws<InvalidDataException>(() => FunctionIndex.Build(PeImage.Open(fixture.ExecutablePath)));
    }

    [Fact]
    public void Build_RangeOutsideExecutableSections_Throws() {
        using var fixture = SyntheticPeBuilder.Create()
            .WithSection(".text", 0x1000, new byte[0x80], executable: true)
            .WithSection(".rdata", 0x2000, new byte[0x20], executable: false)
            .WithRuntimeFunctions(new RuntimeFunctionSpec(0x2000, 0x2010, 0x3000))
            .Write();

        Assert.Throws<InvalidDataException>(() => FunctionIndex.Build(PeImage.Open(fixture.ExecutablePath)));
    }

    [Fact]
    public void Build_OverlappingRanges_Throws() {
        using var fixture = SyntheticPeBuilder.Create()
            .WithSection(".text", 0x1000, new byte[0x80], executable: true)
            .WithRuntimeFunctions(
                new RuntimeFunctionSpec(0x1010, 0x1030, 0x3000),
                new RuntimeFunctionSpec(0x1020, 0x1040, 0x3010))
            .Write();

        Assert.Throws<InvalidDataException>(() => FunctionIndex.Build(PeImage.Open(fixture.ExecutablePath)));
    }

    [Fact]
    public void Build_ExceptionDirectorySizeNotDivisibleByRuntimeFunctionSize_Throws() {
        using var fixture = SyntheticPeBuilder.Create()
            .WithSection(".text", 0x1000, new byte[0x80], executable: true)
            .WithSection(".pdata", 0x2000, new byte[0x10], executable: false)
            .WithExceptionDirectory(0x2000, 13)
            .Write();

        Assert.Throws<InvalidDataException>(() => FunctionIndex.Build(PeImage.Open(fixture.ExecutablePath)));
    }

    [Fact]
    public void Function_CreatesImageAndIndex() {
        var context = TestImages.Function(0x1010, 0x1020);

        Assert.Equal(new Rva(0x1010), context.FunctionIndex.FindByStart(new Rva(0x1010))!.Begin);
        Assert.True(context.Image.TryRead(new Rva(0x1010), 1, out _));
    }
}
