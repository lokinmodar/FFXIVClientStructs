using FFXIVClientStructs.PatchAnalyzer.Cli;

var result = CommandLine.Parse(args);
if (!result.IsSuccess) {
    Console.Error.WriteLine(result.Error);
    Console.Error.WriteLine("Usage: FFXIVClientStructs.PatchAnalyzer analyze --previous-exe <path> --current-exe <path> --data <path> --out <path> [--previous-version <version>] [--current-version <version>]");
    return (int)ExitCode.InvalidInput;
}

return (int)ExitCode.Success;
