namespace FFXIVClientStructs.PatchAnalyzer.Cli;

public sealed record AnalyzerOptions(
    string PreviousExecutable,
    string CurrentExecutable,
    string DataFile,
    string OutputDirectory,
    string? PreviousVersion,
    string? CurrentVersion);

public sealed record CommandLineResult(AnalyzerOptions? Options, string? Error) {
    public bool IsSuccess => Options is not null;
}
