namespace FFXIVClientStructs.PatchAnalyzer.Output;

/// <summary>Writes elapsed stage timings to a console error stream.</summary>
public sealed class ConsoleProgressReporter {
    private readonly TextWriter error;

    /// <summary>Initializes a new instance of the <see cref="ConsoleProgressReporter" /> class.</summary>
    /// <param name="error">The error stream that receives progress output.</param>
    public ConsoleProgressReporter(TextWriter? error = null) => this.error = error ?? Console.Error;

    /// <summary>Writes the elapsed duration of a completed stage.</summary>
    /// <param name="stage">The completed stage name.</param>
    /// <param name="elapsed">The elapsed stage duration.</param>
    public void CompleteStage(string stage, TimeSpan elapsed) {
        ArgumentException.ThrowIfNullOrWhiteSpace(stage);
        error.WriteLine($"{stage}: {elapsed.TotalMilliseconds:F0} ms");
    }
}
