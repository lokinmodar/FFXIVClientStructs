using FFXIVClientStructs.PatchAnalyzer.Cli;
using Xunit;

namespace FFXIVClientStructs.PatchAnalyzer.Tests.Cli;

public class CommandLineTests {
    [Fact]
    public void Parse_CompleteAnalyzeCommand_ReturnsTypedOptions() {
        var result = CommandLine.Parse([
            "analyze",
            "--previous-exe", @"C:\builds\old\ffxiv_dx11.exe",
            "--current-exe", @"C:\builds\new\ffxiv_dx11.exe",
            "--data", @"C:\repo\ida\data.yml",
            "--out", @"C:\repo\artifacts\patch-analysis"
        ]);

        Assert.True(result.IsSuccess);
        Assert.Equal(@"C:\builds\old\ffxiv_dx11.exe", result.Options!.PreviousExecutable);
        Assert.Equal(@"C:\builds\new\ffxiv_dx11.exe", result.Options.CurrentExecutable);
    }

    [Fact]
    public void Parse_MissingRequiredOption_ReturnsUsageError() {
        var result = CommandLine.Parse(["analyze", "--previous-exe", "old.exe"]);

        Assert.False(result.IsSuccess);
        Assert.Contains("--current-exe", result.Error, StringComparison.Ordinal);
    }

    [Fact]
    public void Parse_VersionOverrides_ReturnsTypedOptions() {
        var result = CommandLine.Parse([
            "analyze",
            "--previous-exe", "old.exe",
            "--current-exe", "new.exe",
            "--data", "data.yml",
            "--out", "out",
            "--previous-version", "2026.07.28.0000.0000",
            "--current-version", "2026.07.29.0000.0000"
        ]);

        Assert.True(result.IsSuccess);
        Assert.Equal("2026.07.28.0000.0000", result.Options!.PreviousVersion);
        Assert.Equal("2026.07.29.0000.0000", result.Options.CurrentVersion);
    }

    [Fact]
    public void Parse_UnknownOption_ReturnsUsageError() {
        var result = CommandLine.Parse(["analyze", "--unknown", "value"]);

        Assert.False(result.IsSuccess);
        Assert.Contains("--unknown", result.Error, StringComparison.Ordinal);
    }

    [Fact]
    public void Parse_DuplicateOption_ReturnsUsageError() {
        var result = CommandLine.Parse([
            "analyze",
            "--previous-exe", "old.exe",
            "--previous-exe", "other-old.exe"
        ]);

        Assert.False(result.IsSuccess);
        Assert.Contains("--previous-exe", result.Error, StringComparison.Ordinal);
    }

    [Fact]
    public void Parse_MissingOptionValue_ReturnsUsageError() {
        var result = CommandLine.Parse(["analyze", "--previous-exe"]);

        Assert.False(result.IsSuccess);
        Assert.Contains("--previous-exe", result.Error, StringComparison.Ordinal);
    }

    [Fact]
    public void Parse_UnsupportedVerb_ReturnsUsageError() {
        var result = CommandLine.Parse(["validate"]);

        Assert.False(result.IsSuccess);
        Assert.Contains("analyze", result.Error, StringComparison.Ordinal);
    }
}
