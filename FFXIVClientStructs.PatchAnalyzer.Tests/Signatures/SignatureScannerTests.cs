using FFXIVClientStructs.PatchAnalyzer.Binary;
using FFXIVClientStructs.PatchAnalyzer.Signatures;
using FFXIVClientStructs.PatchAnalyzer.Tests.Fixtures;
using Xunit;

namespace FFXIVClientStructs.PatchAnalyzer.Tests.Signatures;

public class SignatureScannerTests {
    [Fact]
    public void Scan_ReturnsAllMatchesSortedByRva() {
        var image = TestImages.WithExecutableBytes([0xAA, 0xBB, 0x90, 0xAA, 0xBB]);
        var definition = SignatureDefinition.Parse("Test.Match", "AA BB", []);

        var result = SignatureScanner.Scan(image, [definition], 32)[definition.GeneratedName];

        Assert.Equal([new Rva(0x1000), new Rva(0x1003)], result.Matches.Select(match => match.PatternRva));
    }

    [Fact]
    public void Scan_AppliesChainedRel32WithCheckedBounds() {
        var image = TestImages.WithExecutableBytes([
            0xE8, 0x05, 0, 0, 0,
            0x90, 0x90, 0x90, 0x90, 0x90,
            0xE9, 0x01, 0, 0, 0,
            0x90, 0xC3
        ]);
        var definition = SignatureDefinition.Parse("Test.Chain", "E8 ?? ?? ?? ??", [1, 1]);

        var match = Assert.Single(SignatureScanner.Scan(image, [definition], 32)[definition.GeneratedName].Matches);

        Assert.Equal(new Rva(0x1010), match.ResolvedRva);
    }

    [Fact]
    public void Scan_MatchesPatternEndingAtFinalExecutableByte() {
        var image = TestImages.WithExecutableBytes([0x90, 0xAA, 0xBB]);
        var definition = SignatureDefinition.Parse("Test.End", "AA BB", []);

        var match = Assert.Single(SignatureScanner.Scan(image, [definition], 32)[definition.GeneratedName].Matches);

        Assert.Equal(new Rva(0x1001), match.PatternRva);
    }

    [Fact]
    public void Scan_DoesNotMatchPatternAcrossExecutableSections() {
        using var fixture = SyntheticPeBuilder.Create()
            .WithSection(".one", 0x1000, [0xAA], executable: true)
            .WithSection(".two", 0x2000, [0xBB], executable: true)
            .Write();
        var image = PeImage.Open(fixture.ExecutablePath);
        var definition = SignatureDefinition.Parse("Test.Split", "AA BB", []);

        var result = SignatureScanner.Scan(image, [definition], 32)[definition.GeneratedName];

        Assert.Empty(result.Matches);
    }

    [Fact]
    public void Scan_DropsOutOfImageRelativeTargetWithDiagnostic() {
        var image = TestImages.WithExecutableBytes([0xE8, 0xFF, 0x7F, 0x00, 0x00]);
        var definition = SignatureDefinition.Parse("Test.InvalidTarget", "E8 ?? ?? ?? ??", [1]);

        var result = SignatureScanner.Scan(image, [definition], 32)[definition.GeneratedName];

        Assert.Empty(result.Matches);
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Contains("out of image", StringComparison.Ordinal));
    }

    [Fact]
    public void Scan_SupportsWildcardFirstByte() {
        var image = TestImages.WithExecutableBytes([0x90, 0xAA, 0xCC]);
        var definition = SignatureDefinition.Parse("Test.Wildcard", "?? AA", []);

        var match = Assert.Single(SignatureScanner.Scan(image, [definition], 32)[definition.GeneratedName].Matches);

        Assert.Equal(new Rva(0x1000), match.PatternRva);
    }

    [Fact]
    public void Scan_RetainsOnlyCapAndMarksTruncatedWhenAdditionalMatchesExist() {
        var image = TestImages.WithExecutableBytes(Enumerable.Repeat((byte)0xAA, 33).ToArray());
        var definition = SignatureDefinition.Parse("Test.Cap", "AA", []);

        var result = SignatureScanner.Scan(image, [definition], 32)[definition.GeneratedName];

        Assert.Equal(32, result.Matches.Length);
        Assert.True(result.Truncated);
    }

    [Theory]
    [InlineData("")]
    [InlineData("??")]
    [InlineData("?? ??")]
    public void Parse_RejectsEmptyOrAllWildcardPatterns(string patternText) {
        Assert.Throws<ArgumentException>(() => SignatureDefinition.Parse("Test.Invalid", patternText, []));
    }
}
