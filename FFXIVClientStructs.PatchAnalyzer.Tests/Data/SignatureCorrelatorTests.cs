using FFXIVClientStructs.PatchAnalyzer.Binary;
using FFXIVClientStructs.PatchAnalyzer.Data;
using FFXIVClientStructs.PatchAnalyzer.Signatures;
using Xunit;
using YamlDotNet.Core;

namespace FFXIVClientStructs.PatchAnalyzer.Tests.Data;

public class SignatureCorrelatorTests {
    [Fact]
    public void Correlate_FunctionAndInstance_ReturnsExactAddressSpans() {
        const string yaml = """
                            version: 1
                            globals: {}
                            functions: {}
                            classes:
                              Client::Game::Thing:
                                instances:
                                  - ea: 0x142000100 # keep
                                funcs:
                                  0x140001020: ctor
                            """;
        var catalog = DataCatalog.Parse(yaml, 0x140000000);
        var definitions = new[] {
            SignatureDefinition.Parse("FFXIVClientStructs.FFXIV.Client.Game.Thing.Ctor", "40 53", []),
            SignatureDefinition.Parse("FFXIVClientStructs.FFXIV.Client.Game.Thing.Instance", "48 8B 05 ?? ?? ?? ??", [3])
        };

        var entries = SignatureCorrelator.Correlate(definitions, catalog);
        var ctorLocation = Assert.IsType<DataLocation>(entries[0].Location);
        var instanceLocation = Assert.IsType<DataLocation>(entries[1].Location);

        Assert.Equal(new Rva(0x1020), ctorLocation.Rva);
        Assert.Equal(
            "0x140001020",
            yaml.AsSpan(
                ctorLocation.SourceSpan.Start,
                ctorLocation.SourceSpan.Length).ToString());
        Assert.Equal(new Rva(0x2000100), instanceLocation.Rva);
    }

    [Fact]
    public void Correlate_StaticVirtualTableAndGlobal_MapsTheirNativeLocations() {
        const string yaml = """
                            version: 1
                            globals:
                              0x142000010: g_Client::Game::Thing::Value
                            functions: {}
                            classes:
                              Client::Game::Thing:
                                vtbls:
                                  - ea: 0x142000100
                            """;
        var entries = SignatureCorrelator.Correlate([
            SignatureDefinition.Parse("FFXIVClientStructs.FFXIV.Client.Game.Thing.StaticVirtualTable", "48 8D", []),
            SignatureDefinition.Parse("FFXIVClientStructs.FFXIV.Client.Game.Thing.Value", "48 89", [])
        ], DataCatalog.Parse(yaml, 0x140000000));
        var virtualTableLocation = Assert.IsType<DataLocation>(entries[0].Location);
        var globalLocation = Assert.IsType<DataLocation>(entries[1].Location);

        Assert.Equal(LocationKind.VirtualTable, virtualTableLocation.Kind);
        Assert.Equal(new Rva(0x2000100), virtualTableLocation.Rva);
        Assert.Equal(LocationKind.Global, globalLocation.Kind);
        Assert.Equal(new Rva(0x2000010), globalLocation.Rva);
    }

    [Fact]
    public void Correlate_HavokAndAbsentDefinitions_ReturnMissingEntries() {
        var catalog = DataCatalog.Parse("version: 1\nglobals: {}\nfunctions: {}\nclasses: {}\n", 0x140000000);

        var entries = SignatureCorrelator.Correlate([
            SignatureDefinition.Parse("FFXIVClientStructs.FFXIV.Havok.hkBase", "48 83", []),
            SignatureDefinition.Parse("FFXIVClientStructs.FFXIV.Client.Game.Missing.Update", "40 55", [])
        ], catalog);

        Assert.All(entries, entry => Assert.Equal(DataCorrelationStatus.Missing, entry.CorrelationStatus));
    }

    [Fact]
    public void Correlate_DuplicateNativeNames_ReturnsAmbiguousDiagnostic() {
        const string yaml = """
                            version: 1
                            globals: {}
                            functions:
                              0x140001000: Client::Game::Thing::Update
                              0x140002000: Client::Game::Thing::Update
                            classes: {}
                            """;

        var entry = Assert.Single(SignatureCorrelator.Correlate([
            SignatureDefinition.Parse("FFXIVClientStructs.FFXIV.Client.Game.Thing.Update", "40 55", [])
        ], DataCatalog.Parse(yaml, 0x140000000)));

        Assert.Equal(DataCorrelationStatus.Ambiguous, entry.CorrelationStatus);
        Assert.Null(entry.Location);
        Assert.NotNull(entry.Diagnostic);
    }

    [Fact]
    public void Correlate_CrLfSource_PreservesExactAddressSpan() {
        const string yaml = "version: 1\r\nglobals: {}\r\nfunctions:\r\n  0x140001000: Client::Game::Thing::Update\r\nclasses: {}\r\n";
        var entry = Assert.Single(SignatureCorrelator.Correlate([
            SignatureDefinition.Parse("FFXIVClientStructs.FFXIV.Client.Game.Thing.Update", "40 55", [])
        ], DataCatalog.Parse(yaml, 0x140000000)));
        var location = Assert.IsType<DataLocation>(entry.Location);

        Assert.Equal(
            "0x140001000",
            yaml.AsSpan(location.SourceSpan.Start, location.SourceSpan.Length).ToString());
    }

    [Fact]
    public void Correlate_MultipleInstancesAndVirtualTables_UsesThePrimaryEntries() {
        const string yaml = """
                            version: 1
                            globals: {}
                            functions: {}
                            classes:
                                Client::Game::Thing:
                                    instances:
                                        - ea: 0x142000100
                                        - ea: 0x142000200
                                    vtbls:
                                        - ea: 0x142000300
                                        - ea: 0x142000400
                            """;

        var entries = SignatureCorrelator.Correlate([
            SignatureDefinition.Parse("FFXIVClientStructs.FFXIV.Client.Game.Thing.Instance", "48 8B", []),
            SignatureDefinition.Parse("FFXIVClientStructs.FFXIV.Client.Game.Thing.StaticVirtualTable", "48 8D", [])
        ], DataCatalog.Parse(yaml, 0x140000000));

        Assert.Equal(new Rva(0x2000100), entries[0].Location!.Rva);
        Assert.Equal(new Rva(0x2000300), entries[1].Location!.Rva);
    }

    [Fact]
    public void Correlate_DuplicateClassDeclarations_ReturnsAmbiguousForInstanceAndVirtualTable() {
        const string yaml = """
                            version: 1
                            globals: {}
                            functions: {}
                            classes:
                              Client::Game::Thing:
                                instances:
                                  - ea: 0x142000100
                                vtbls:
                                  - ea: 0x142000200
                              Client::Game::Thing:
                                instances:
                                  - ea: 0x142000300
                                vtbls:
                                  - ea: 0x142000400
                            """;

        var entries = SignatureCorrelator.Correlate([
            SignatureDefinition.Parse("FFXIVClientStructs.FFXIV.Client.Game.Thing.Instance", "48 8B", []),
            SignatureDefinition.Parse("FFXIVClientStructs.FFXIV.Client.Game.Thing.StaticVirtualTable", "48 8D", [])
        ], DataCatalog.Parse(yaml, 0x140000000));

        Assert.All(entries, entry => Assert.Equal(DataCorrelationStatus.Ambiguous, entry.CorrelationStatus));
        Assert.All(entries, entry => Assert.Null(entry.Location));
    }

    [Fact]
    public void Parse_DuplicateClassAndUnrelatedDuplicateKey_ThrowsYamlException() {
        const string yaml = """
                            version: 1
                            globals: {}
                            functions: {}
                            classes:
                              Client::Game::Thing:
                                instances:
                                  - ea: 0x142000100
                              Client::Game::Thing:
                                instances:
                                  - ea: 0x142000200
                            globals: {}
                            """;

        Assert.Throws<YamlException>(() => DataCatalog.Parse(yaml, 0x140000000));
    }

    [Theory]
    [InlineData("""
                version: 1
                globals: {}
                functions: {}
                classes:
                  Client::Game::Thing:
                    metadata: first
                    metadata: second
                  Client::Game::Thing:
                    instances:
                      - ea: 0x142000300
                """)]
    [InlineData("""
                version: 1
                globals: {}
                functions: {}
                classes:
                  Client::Game::Thing:
                    instances:
                      - ea: 0x142000100
                        ea: 0x142000200
                  Client::Game::Thing:
                    instances:
                      - ea: 0x142000300
                """)]
    public void Parse_DuplicateClassAndUnrelatedNestedDuplicateKey_ThrowsYamlException(string yaml) {
        Assert.Throws<YamlException>(() => DataCatalog.Parse(yaml, 0x140000000));
    }

    [Theory]
    [InlineData("version: []\nglobals: {}\nfunctions: {}\nclasses: {}\n")]
    [InlineData("version: 1\nglobals: []\nfunctions: {}\nclasses: {}\n")]
    [InlineData("version: 1\nglobals: {}\nfunctions: {}\nclasses:\n  Client::Game::Thing:\n    funcs: []\n")]
    [InlineData("version: 1\nglobals: {}\nfunctions: {}\nclasses:\n  Client::Game::Thing:\n    instances: {}\n")]
    [InlineData("version: 1\nglobals: {}\nfunctions: {}\nclasses:\n  Client::Game::Thing:\n    vtbls:\n      - ea: {}\n")]
    public void Parse_InvalidSemanticShape_ThrowsFormatException(string yaml) {
        Assert.Throws<FormatException>(() => DataCatalog.Parse(yaml, 0x140000000));
    }
}
