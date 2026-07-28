using FFXIVClientStructs.PatchAnalyzer.Signatures;
using InteropGenerator.Runtime;
using Xunit;

namespace FFXIVClientStructs.PatchAnalyzer.Tests.Signatures;

public class GeneratedSignatureInventoryTests {
    [Fact]
    public void Parse_PreservesWildcardMaskAndCanonicalText() {
        var pattern = SignaturePattern.Parse("48 8B ?? E8 ?? ?? ?? ??");

        Assert.Equal("48 8B ?? E8 ?? ?? ?? ??", pattern.ToString());
        Assert.Equal(new byte[] { 0xFF, 0xFF, 0, 0xFF, 0, 0, 0, 0 }, pattern.Mask);
    }

    [Fact]
    public void Load_ContainsEveryRegisteredGeneratedAddressInOrdinalOrder() {
        var inventory = new GeneratedSignatureInventory();

        var definitions = inventory.Load();

        Assert.Equal(Resolver.GetInstance.Addresses.Count, definitions.Length);
        Assert.Equal(
            definitions.Select(definition => definition.GeneratedName).Order(StringComparer.Ordinal),
            definitions.Select(definition => definition.GeneratedName));
        Assert.All(definitions, definition => Assert.NotEmpty(definition.Pattern.Bytes));
    }
}
