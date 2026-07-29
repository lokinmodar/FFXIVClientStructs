using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using FFXIVClientStructs.PatchAnalyzer.Analysis;

namespace FFXIVClientStructs.PatchAnalyzer.Output;

/// <summary>Renders deterministic JSON reports and writes them atomically.</summary>
public static class ReportWriter {
    private static readonly UTF8Encoding Utf8WithoutBom = new(false);
    private static readonly JsonSerializerOptions SerializerOptions = new() {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.SnakeCaseLower) }
    };

    /// <summary>Renders a deterministic report to <paramref name="destination" />.</summary>
    /// <param name="result">The analysis result to render.</param>
    /// <param name="destination">The destination stream.</param>
    public static void Render(PatchAnalysisResult result, Stream destination) {
        ArgumentNullException.ThrowIfNull(result);
        ArgumentNullException.ThrowIfNull(destination);

        var json = JsonSerializer.Serialize(AnalysisReport.Create(result), SerializerOptions).Replace("\r\n", "\n", StringComparison.Ordinal) + "\n";
        using var writer = new StreamWriter(destination, Utf8WithoutBom, leaveOpen: true);
        writer.Write(json);
        writer.Flush();
    }

    /// <summary>Writes a deterministic report atomically.</summary>
    /// <param name="result">The analysis result to render.</param>
    /// <param name="destinationPath">The report destination path.</param>
    /// <param name="cancellationToken">A token that cancels the write.</param>
    public static void Write(PatchAnalysisResult result, string destinationPath, CancellationToken cancellationToken = default) =>
        AtomicFileWriter.Write(destinationPath, destination => Render(result, destination), cancellationToken);
}
