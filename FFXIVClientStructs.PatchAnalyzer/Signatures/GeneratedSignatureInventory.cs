using System.Collections.Immutable;
using InteropGenerator.Runtime;

namespace FFXIVClientStructs.PatchAnalyzer.Signatures;

public interface ISignatureInventory {
    ImmutableArray<SignatureDefinition> Load();
}

public sealed class GeneratedSignatureInventory : ISignatureInventory {
    private static readonly Lazy<ImmutableArray<SignatureDefinition>> Definitions = new(CreateDefinitions);

    public ImmutableArray<SignatureDefinition> Load() => Definitions.Value;

    private static ImmutableArray<SignatureDefinition> CreateDefinitions() {
        FFXIVClientStructs.Interop.Generated.Addresses.Register();
        return Resolver.GetInstance.Addresses
            .Select(address => SignatureDefinition.Parse(address.Name, address.String, address.RelativeFollowOffsets))
            .OrderBy(definition => definition.GeneratedName, StringComparer.Ordinal)
            .ToImmutableArray();
    }
}
