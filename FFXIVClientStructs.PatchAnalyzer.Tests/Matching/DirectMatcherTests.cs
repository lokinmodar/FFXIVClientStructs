using System.Collections.Immutable;
using FFXIVClientStructs.PatchAnalyzer.Analysis;
using FFXIVClientStructs.PatchAnalyzer.Binary;
using FFXIVClientStructs.PatchAnalyzer.Data;
using FFXIVClientStructs.PatchAnalyzer.Matching;
using FFXIVClientStructs.PatchAnalyzer.Signatures;
using Xunit;

namespace FFXIVClientStructs.PatchAnalyzer.Tests.Matching;

public class DirectMatcherTests {
    [Theory]
    [MemberData(nameof(DirectCases))]
    public void Match_ClassifiesRuleConditions(
        DataCorrelationStatus correlation,
        Rva? expectedOld,
        Rva[] oldResults,
        Rva[] currentResults,
        SymbolStatus expectedStatus) {
        var analysis = DirectMatcher.Match(
            TestCatalog.Entry(correlation, expectedOld),
            TestScans.Result(oldResults),
            TestScans.Result(currentResults));

        Assert.Equal(expectedStatus, analysis.Status);
    }

    public static TheoryData<DataCorrelationStatus, Rva?, Rva[], Rva[], SymbolStatus> DirectCases => new() {
        { DataCorrelationStatus.Missing, null, [], [], SymbolStatus.NotInData },
        { DataCorrelationStatus.Matched, new Rva(0x1000), [new Rva(0x1010)], [], SymbolStatus.StaleSource },
        { DataCorrelationStatus.Matched, new Rva(0x1000), [new Rva(0x1000)], [new Rva(0x2000)], SymbolStatus.DirectUnique },
        { DataCorrelationStatus.Matched, new Rva(0x1000), [new Rva(0x1000)], [], SymbolStatus.Missing },
        { DataCorrelationStatus.Matched, new Rva(0x1000), [new Rva(0x1000)], [new Rva(0x2000), new Rva(0x3000)], SymbolStatus.Ambiguous }
    };

    [Theory]
    [InlineData(DataCorrelationStatus.Ambiguous, SymbolStatus.Ambiguous)]
    [InlineData(DataCorrelationStatus.Invalid, SymbolStatus.AnalysisError)]
    public void Match_NonMatchedCorrelation_RemainsNonDirectWithDiagnostic(
        DataCorrelationStatus correlation,
        SymbolStatus expectedStatus) {
        var analysis = DirectMatcher.Match(
            TestCatalog.Entry(correlation, null),
            TestScans.Result(new Rva(0x1000)),
            TestScans.Result(new Rva(0x2000)));

        Assert.Equal(expectedStatus, analysis.Status);
        Assert.Null(analysis.CurrentTarget);
        Assert.NotEmpty(analysis.Diagnostics);
    }

    [Fact]
    public void Match_TruncatedOldScan_RemainsNonDirectWithDiagnostic() {
        var analysis = DirectMatcher.Match(
            TestCatalog.Entry(DataCorrelationStatus.Matched, new Rva(0x1000)),
            TestScans.Result([new Rva(0x1000)], truncated: true),
            TestScans.Result(new Rva(0x2000)));

        Assert.Equal(SymbolStatus.AnalysisError, analysis.Status);
        Assert.Null(analysis.CurrentTarget);
        Assert.NotEmpty(analysis.Diagnostics);
    }

    [Fact]
    public void Match_TruncatedCurrentScan_IsNotDirectUnique() {
        var analysis = DirectMatcher.Match(
            TestCatalog.Entry(DataCorrelationStatus.Matched, new Rva(0x1000)),
            TestScans.Result(new Rva(0x1000)),
            TestScans.Result([new Rva(0x2000)], truncated: true));

        Assert.Equal(SymbolStatus.Ambiguous, analysis.Status);
        Assert.Null(analysis.CurrentTarget);
        Assert.NotEmpty(analysis.Diagnostics);
    }

    [Fact]
    public void Match_DirectResult_UsesEmptyImmutableEvidenceAndDiagnostics() {
        var analysis = DirectMatcher.Match(
            TestCatalog.Entry(DataCorrelationStatus.Matched, new Rva(0x1000)),
            TestScans.Result(new Rva(0x1000)),
            TestScans.Result(new Rva(0x2000)));

        Assert.Equal(new Rva(0x2000), analysis.CurrentTarget);
        Assert.Empty(analysis.RecoveryEvidence);
        Assert.Null(analysis.SuggestedSignature);
        Assert.Empty(analysis.Diagnostics);
    }

    private static class TestCatalog {
        public static SignatureCatalogEntry Entry(DataCorrelationStatus correlation, Rva? expectedOld) {
            var signature = SignatureDefinition.Parse("Test.Direct", "40 53", []);
            var location = expectedOld is { } rva
                ? new DataLocation("Test::Direct", LocationKind.Function, new PreferredVa(rva.Value), rva, new SourceSpan(0, 0))
                : null;

            return new SignatureCatalogEntry(signature, correlation, location, null);
        }
    }

    private static class TestScans {
        public static SignatureScanResult Result(params Rva[] rvas) => Result(rvas, truncated: false);

        public static SignatureScanResult Result(Rva[] rvas, bool truncated) => new(
            rvas.Select(rva => new SignatureMatch(rva, rva)).ToImmutableArray(),
            truncated,
            []);
    }
}
