using System.Text;
using FFXIVClientStructs.PatchAnalyzer.Analysis;
using FFXIVClientStructs.PatchAnalyzer.Binary;
using FFXIVClientStructs.PatchAnalyzer.Data;

namespace FFXIVClientStructs.PatchAnalyzer.Output;

/// <summary>Renders review-required candidate YAML through exact source-token replacements.</summary>
public static class CandidateYamlWriter {
    private const string Header = "# REVIEW REQUIRED: generated candidate; verify before applying.\n";
    private static readonly UTF8Encoding Utf8WithoutBom = new(false);

    /// <summary>Renders a review-required candidate YAML document.</summary>
    /// <param name="result">The analysis result that supplies source text and accepted replacements.</param>
    /// <returns>The rendered candidate YAML.</returns>
    public static string Render(PatchAnalysisResult result) {
        ArgumentNullException.ThrowIfNull(result);
        if (!string.Equals(result.RunStatus, "succeeded", StringComparison.Ordinal))
            throw new InvalidOperationException("Candidate YAML is only written for succeeded runs.");

        return Render(result, result.Data.SourceText);
    }

    private static string Render(PatchAnalysisResult result, string source) {
        var replacements = BuildReplacements(result, source);
        foreach (var replacement in replacements.OrderByDescending(replacement => replacement.Span.Start)) {
            var actual = source.AsSpan(replacement.Span.Start, replacement.Span.Length);
            if (!actual.SequenceEqual(replacement.ExpectedOldToken.AsSpan()))
                throw new InvalidOperationException($"Source token at offset {replacement.Span.Start} no longer matches the expected old token.");

            source = string.Concat(source.AsSpan(0, replacement.Span.Start), replacement.NewToken, source.AsSpan(replacement.Span.Start + replacement.Span.Length));
        }

        return Header + NormalizeLineEndings(source).TrimEnd('\n') + '\n';
    }

    /// <summary>Renders candidate YAML to <paramref name="destination" /> using UTF-8 without a byte-order mark.</summary>
    /// <param name="result">The analysis result that supplies source text and accepted replacements.</param>
    /// <param name="destination">The destination stream.</param>
    public static void Render(PatchAnalysisResult result, Stream destination) {
        ArgumentNullException.ThrowIfNull(destination);
        using var writer = new StreamWriter(destination, Utf8WithoutBom, leaveOpen: true);
        writer.Write(Render(result));
        writer.Flush();
    }

    /// <summary>Writes candidate YAML atomically while preventing replacement of its source file.</summary>
    /// <param name="result">The analysis result that supplies source text and accepted replacements.</param>
    /// <param name="inputPath">The source YAML path.</param>
    /// <param name="outputPath">The candidate YAML path.</param>
    /// <param name="cancellationToken">A token that cancels the write.</param>
    public static void Write(PatchAnalysisResult result, string inputPath, string outputPath, CancellationToken cancellationToken = default) {
        ArgumentNullException.ThrowIfNull(result);
        ArgumentException.ThrowIfNullOrWhiteSpace(inputPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(outputPath);
        if (string.Equals(Path.GetFullPath(inputPath), Path.GetFullPath(outputPath), StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Candidate YAML output path must differ from the input path.", nameof(outputPath));
        if (!string.Equals(result.RunStatus, "succeeded", StringComparison.Ordinal))
            throw new InvalidOperationException("Candidate YAML is only written for succeeded runs.");

        var inputSource = File.ReadAllText(inputPath);
        if (!string.Equals(inputSource, result.Data.SourceText, StringComparison.Ordinal))
            throw new InvalidOperationException("The candidate YAML input file no longer matches the analyzed source text.");

        AtomicFileWriter.Write(outputPath, destination => Render(result, inputSource, destination), cancellationToken);
    }

    private static void Render(PatchAnalysisResult result, string source, Stream destination) {
        using var writer = new StreamWriter(destination, Utf8WithoutBom, leaveOpen: true);
        writer.Write(Render(result, source));
        writer.Flush();
    }

    private static IReadOnlyList<Replacement> BuildReplacements(PatchAnalysisResult result, string source) {
        var replacements = new List<Replacement>();
        var version = result.Configuration.CurrentVersionOverride;
        if (version is null && string.Equals(result.CurrentBinary.VersionSource, "ffxivgame.ver", StringComparison.Ordinal))
            version = result.CurrentBinary.GameVersion;
        if (version is not null)
            replacements.Add(Replacement.FromSource(source, result.Data.VersionSourceSpan, version));

        foreach (var symbol in result.Symbols) {
            if (symbol.CurrentTarget is null)
                continue;

            var locations = symbol.PreviousDataRva is { } previousDataRva
                ? result.Data.Locations.Where(location => location.Rva == previousDataRva).ToArray()
                : [];
            if (locations.Length == 0)
                continue;
            if (!IsAccepted(symbol.Status))
                throw new InvalidOperationException($"Cannot replace a non-accepted symbol status: {symbol.Status}.");
            if (locations.Length != 1)
                throw new InvalidOperationException($"Cannot replace '{symbol.GeneratedName}' because its data source location is ambiguous.");

            var location = locations[0];
            var currentAddress = checked(result.CurrentImageBase + symbol.CurrentTarget.Value.Value);
            replacements.Add(Replacement.FromSource(source, location.SourceSpan, $"0x{currentAddress:X}"));
        }

        ValidateSpans(replacements);
        return replacements;
    }

    private static bool IsAccepted(SymbolStatus status) => status is SymbolStatus.DirectUnique or SymbolStatus.StructuralRecovered or SymbolStatus.CallerRecovered;

    private static string NormalizeLineEndings(string value) => value.Replace("\r\n", "\n", StringComparison.Ordinal).Replace('\r', '\n');

    private static void ValidateSpans(IReadOnlyList<Replacement> replacements) {
        foreach (var replacement in replacements.OrderBy(replacement => replacement.Span.Start)) {
            if (replacement.Span.Start < 0 || replacement.Span.Length < 0)
                throw new InvalidOperationException("Replacement source span is invalid.");
        }

        var ordered = replacements.OrderBy(replacement => replacement.Span.Start).ToArray();
        for (var index = 1; index < ordered.Length; index++) {
            var previous = ordered[index - 1];
            var current = ordered[index];
            if (current.Span.Start == previous.Span.Start && current.Span.Length == previous.Span.Length)
                throw new InvalidOperationException("Replacement source spans must be unique.");
            if (current.Span.Start < previous.Span.Start + previous.Span.Length)
                throw new InvalidOperationException("Replacement source spans must not overlap.");
        }
    }

    private sealed record Replacement(SourceSpan Span, string ExpectedOldToken, string NewToken) {
        public static Replacement FromSource(string source, SourceSpan span, string newToken) {
            if (span.Start < 0 || span.Length < 0 || span.Start > source.Length - span.Length)
                throw new InvalidOperationException("Replacement source span is outside the YAML source text.");
            return new Replacement(span, source.Substring(span.Start, span.Length), newToken);
        }
    }
}
