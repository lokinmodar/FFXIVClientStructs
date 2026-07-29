using System.Collections.Immutable;
using System.Globalization;

namespace FFXIVClientStructs.PatchAnalyzer.Signatures;

public sealed record SignaturePattern(ImmutableArray<byte> Bytes, ImmutableArray<byte> Mask) {
    public static SignaturePattern Parse(string text) {
        ArgumentException.ThrowIfNullOrWhiteSpace(text);

        var tokens = text.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var bytes = ImmutableArray.CreateBuilder<byte>(tokens.Length);
        var mask = ImmutableArray.CreateBuilder<byte>(tokens.Length);

        foreach (var token in tokens) {
            if (token == "??") {
                bytes.Add(0);
                mask.Add(0);
                continue;
            }

            if (token.Length != 2 || !byte.TryParse(token, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out var value))
                throw new FormatException($"Invalid signature token '{token}'.");

            bytes.Add(value);
            mask.Add(byte.MaxValue);
        }

        if (bytes.Count == 0 || mask.All(value => value == 0))
            throw new ArgumentException("A signature pattern must contain at least one non-wildcard byte.", nameof(text));

        return new SignaturePattern(bytes.MoveToImmutable(), mask.MoveToImmutable());
    }

    public override string ToString() => string.Join(' ', Bytes.Select((value, index) => Mask[index] == 0 ? "??" : value.ToString("X2", CultureInfo.InvariantCulture)));
}
