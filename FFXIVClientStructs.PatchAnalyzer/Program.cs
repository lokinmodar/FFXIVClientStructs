using FFXIVClientStructs.PatchAnalyzer.Cli;
using FFXIVClientStructs.PatchAnalyzer.Analysis;

using var cancellation = new CancellationTokenSource();
Console.CancelKeyPress += (_, eventArgs) => {
    eventArgs.Cancel = true;
    cancellation.Cancel();
};

var result = CommandLine.Parse(args);
if (!result.IsSuccess) {
    Console.Error.WriteLine(result.Error);
    Console.Error.WriteLine("Usage: FFXIVClientStructs.PatchAnalyzer analyze --previous-exe <path> --current-exe <path> --data <path> --out <path> [--previous-version <version>] [--current-version <version>]");
    return (int)ExitCode.InvalidInput;
}

return (int)await PatchAnalyzerApplication.CreateDefault()
    .RunAsync(result.Options!, cancellation.Token);
