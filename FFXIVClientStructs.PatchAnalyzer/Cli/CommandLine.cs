namespace FFXIVClientStructs.PatchAnalyzer.Cli;

public static class CommandLine {
    private static readonly string[] RequiredOptions = ["--previous-exe", "--current-exe", "--data", "--out"];

    public static CommandLineResult Parse(string[] args) {
        if (args.Length == 0 || args[0] != "analyze")
            return Error("The only supported verb is analyze.");

        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var index = 1; index < args.Length; index += 2) {
            var option = args[index];
            if (!IsKnownOption(option))
                return Error($"Unknown option: {option}");

            if (values.ContainsKey(option))
                return Error($"Duplicate option: {option}");

            if (index + 1 >= args.Length || args[index + 1].StartsWith("--", StringComparison.Ordinal))
                return Error($"Option {option} requires a value.");

            values.Add(option, args[index + 1]);
        }

        foreach (var requiredOption in RequiredOptions) {
            if (!values.ContainsKey(requiredOption))
                return Error($"Required option {requiredOption} was not provided.");
        }

        return new CommandLineResult(
            new AnalyzerOptions(
                values["--previous-exe"],
                values["--current-exe"],
                values["--data"],
                values["--out"],
                values.GetValueOrDefault("--previous-version"),
                values.GetValueOrDefault("--current-version")),
            null);
    }

    private static bool IsKnownOption(string option) => option is "--previous-exe" or "--current-exe" or "--data" or "--out" or "--previous-version" or "--current-version";

    private static CommandLineResult Error(string error) => new(null, error);
}
