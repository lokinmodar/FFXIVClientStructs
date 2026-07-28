using System.Collections.Immutable;
using System.Diagnostics;
using FFXIVClientStructs.PatchAnalyzer.Binary;
using FFXIVClientStructs.PatchAnalyzer.Cli;
using FFXIVClientStructs.PatchAnalyzer.Data;
using FFXIVClientStructs.PatchAnalyzer.Decoding;
using FFXIVClientStructs.PatchAnalyzer.Graph;
using FFXIVClientStructs.PatchAnalyzer.Matching;
using FFXIVClientStructs.PatchAnalyzer.Output;
using FFXIVClientStructs.PatchAnalyzer.Signatures;

namespace FFXIVClientStructs.PatchAnalyzer.Analysis;

/// <summary>Coordinates patch analysis from validated inputs through deterministic artifacts.</summary>
public sealed class PatchAnalyzerApplication {
    private const int MatchLimit = 10;
    private const int MaximumSignatureBytes = 96;

    private readonly ISignatureInventory signatureInventory;
    private readonly IInstructionDecoder instructionDecoder;

    /// <summary>Initializes an application with the inventory and decoder used for one analysis run.</summary>
    public PatchAnalyzerApplication(ISignatureInventory signatureInventory, IInstructionDecoder instructionDecoder) {
        this.signatureInventory = signatureInventory ?? throw new ArgumentNullException(nameof(signatureInventory));
        this.instructionDecoder = instructionDecoder ?? throw new ArgumentNullException(nameof(instructionDecoder));
    }

    /// <summary>Creates an application using the production generated inventory and Iced decoder.</summary>
    public static PatchAnalyzerApplication CreateDefault() => new(new GeneratedSignatureInventory(), new IcedInstructionDecoder());

    /// <summary>Runs the analyzer and returns a process-compatible exit code.</summary>
    public Task<ExitCode> RunAsync(AnalyzerOptions options, CancellationToken cancellationToken) {
        ArgumentNullException.ThrowIfNull(options);

        PreflightState? preflight = null;
        var symbols = ImmutableArray<SymbolAnalysis>.Empty;
        var stageMilliseconds = new SortedDictionary<string, long>(StringComparer.Ordinal);
        try {
            cancellationToken.ThrowIfCancellationRequested();
            if (!TryPreflight(options, cancellationToken, out preflight, out var diagnostic)) {
                Console.Error.WriteLine(diagnostic);
                return Task.FromResult(ExitCode.InvalidInput);
            }

            cancellationToken.ThrowIfCancellationRequested();
            var validatedPreflight = preflight!;
            Directory.CreateDirectory(validatedPreflight.OutputDirectory);
            var result = RunPipeline(validatedPreflight, symbols, stageMilliseconds, cancellationToken, out symbols);
            ValidateTerminalSymbols(result.Symbols, validatedPreflight.Signatures);

            cancellationToken.ThrowIfCancellationRequested();
            ReportWriter.Write(result, Path.Combine(validatedPreflight.OutputDirectory, "report.json"), cancellationToken);
            CandidateYamlWriter.Write(result, validatedPreflight.DataFile, Path.Combine(validatedPreflight.OutputDirectory, "data.candidate.yml"), cancellationToken);
            return Task.FromResult(ExitCode.Success);
        } catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) {
            Console.Error.WriteLine("Patch analysis was cancelled.");
            return Task.FromResult(ExitCode.FatalAnalysis);
        } catch (Exception exception) {
            Console.Error.WriteLine($"Fatal patch analysis failure: {exception.Message}");
            if (preflight is not null) {
                var failed = CreateResult("failed", preflight, symbols, stageMilliseconds);
                TryWriteFailedReport(failed, preflight.OutputDirectory);
            }

            return Task.FromResult(ExitCode.FatalAnalysis);
        }
    }

    private bool TryPreflight(
        AnalyzerOptions options,
        CancellationToken cancellationToken,
        out PreflightState? state,
        out string diagnostic) {
        state = null;
        diagnostic = string.Empty;
        try {
            var previousExecutable = Path.GetFullPath(options.PreviousExecutable);
            var currentExecutable = Path.GetFullPath(options.CurrentExecutable);
            var dataFile = Path.GetFullPath(options.DataFile);
            var outputDirectory = Path.GetFullPath(options.OutputDirectory);
            cancellationToken.ThrowIfCancellationRequested();

            EnsureReadable(previousExecutable, "previous executable");
            EnsureReadable(currentExecutable, "current executable");
            EnsureReadable(dataFile, "data file");
            EnsureOutputDoesNotOverlapInput(outputDirectory, previousExecutable, currentExecutable, dataFile);

            var previousImage = PeImage.Open(previousExecutable);
            var currentImage = PeImage.Open(currentExecutable);
            if (string.Equals(previousImage.Identity.Sha256, currentImage.Identity.Sha256, StringComparison.Ordinal))
                throw new InvalidDataException("The previous and current executables have identical SHA-256 hashes.");

            var data = DataCatalog.Parse(File.ReadAllText(dataFile), previousImage.ImageBase);
            var expectedPreviousVersion = options.PreviousVersion ?? previousImage.Identity.GameVersion;
            if (expectedPreviousVersion is not null && !string.Equals(data.Version, expectedPreviousVersion, StringComparison.Ordinal))
                throw new InvalidDataException("data.yml version does not match the previous executable version.");

            var previousFunctions = FunctionIndex.Build(previousImage);
            var currentFunctions = FunctionIndex.Build(currentImage);
            ValidateDecoderPreflight();
            var signatures = signatureInventory.Load();
            if (signatures.IsDefault)
                throw new InvalidDataException("The generated signature inventory was not initialized.");
            if (signatures.GroupBy(signature => signature.GeneratedName, StringComparer.Ordinal).Any(group => group.Count() != 1))
                throw new InvalidDataException("The generated signature inventory contains duplicate names.");

            state = new PreflightState(
                previousExecutable,
                currentExecutable,
                dataFile,
                outputDirectory,
                previousImage,
                currentImage,
                previousFunctions,
                currentFunctions,
                data,
                signatures,
                new AnalysisConfiguration(
                    MatchLimit,
                    MaximumSignatureBytes,
                    CallSiteFingerprint.InstructionRadius,
                    options.PreviousVersion,
                    options.CurrentVersion));
            return true;
        } catch (OperationCanceledException) {
            throw;
        } catch (Exception exception) {
            diagnostic = $"Invalid analyzer input: {exception.Message}";
            return false;
        }
    }

    private PatchAnalysisResult RunPipeline(
        PreflightState preflight,
        ImmutableArray<SymbolAnalysis> initialSymbols,
        SortedDictionary<string, long> stageMilliseconds,
        CancellationToken cancellationToken,
        out ImmutableArray<SymbolAnalysis> symbols) {
        symbols = initialSymbols;
        var reporter = new ConsoleProgressReporter();
        var signatures = preflight.Signatures;
        var correlated = RunStage("correlate", reporter, stageMilliseconds, cancellationToken,
            () => SignatureCorrelator.Correlate(signatures, preflight.Data));
        var previousScans = RunStage("scan previous", reporter, stageMilliseconds, cancellationToken,
            () => SignatureScanner.Scan(preflight.PreviousImage, signatures, preflight.Configuration.MatchLimit));
        var currentScans = RunStage("scan current", reporter, stageMilliseconds, cancellationToken,
            () => SignatureScanner.Scan(preflight.CurrentImage, signatures, preflight.Configuration.MatchLimit));
        var previousGraph = RunStage("graph previous", reporter, stageMilliseconds, cancellationToken,
            () => CallGraphBuilder.Build(preflight.PreviousImage, preflight.PreviousFunctions, instructionDecoder));
        var currentGraph = RunStage("graph current", reporter, stageMilliseconds, cancellationToken,
            () => CallGraphBuilder.Build(preflight.CurrentImage, preflight.CurrentFunctions, instructionDecoder));

        var direct = ImmutableArray.CreateBuilder<SymbolAnalysis>(correlated.Length);
        foreach (var entry in correlated) {
            cancellationToken.ThrowIfCancellationRequested();
            direct.Add(WithSymbolIsolation(
                entry,
                previousScans[entry.Signature.GeneratedName],
                currentScans[entry.Signature.GeneratedName],
                () => DirectMatcher.Match(
                    entry,
                    previousScans[entry.Signature.GeneratedName],
                    currentScans[entry.Signature.GeneratedName])));
        }

        var functionMatches = RunStage("whole-function matching", reporter, stageMilliseconds, cancellationToken,
            () => BuildFunctionMatches(previousGraph, currentGraph, cancellationToken));

        var structurallyRecovered = ImmutableArray.CreateBuilder<SymbolAnalysis>(direct.Count);
        foreach (var analysis in direct) {
            cancellationToken.ThrowIfCancellationRequested();
            structurallyRecovered.Add(WithSymbolIsolation(
                analysis,
                () => ApplyStructuralRecovery(analysis, functionMatches, preflight.CurrentImage, preflight.CurrentFunctions, instructionDecoder)));
        }

        var signedCallerAnchors = direct
            .Where(analysis => analysis.Status == SymbolStatus.DirectUnique && analysis.PreviousDataRva is not null)
            .GroupBy(analysis => analysis.PreviousDataRva!.Value)
            .Where(group => group.Count() == 1)
            .ToDictionary(group => group.Key, group => group.Single());
        var callerContext = new CallerRecoveryContext(
            preflight.Configuration.CallSiteInstructionRadius,
            functionMatches,
            signedCallerAnchors,
            preflight.PreviousImage,
            preflight.CurrentImage,
            instructionDecoder);
        var callerRecovered = ImmutableArray.CreateBuilder<SymbolAnalysis>(structurallyRecovered.Count);
        foreach (var analysis in structurallyRecovered) {
            cancellationToken.ThrowIfCancellationRequested();
            callerRecovered.Add(WithSymbolIsolation(
                analysis,
                () => CallerRecoveryMatcher.Recover(analysis, previousGraph, currentGraph, callerContext)));
        }

        var classified = ImmutableArray.CreateBuilder<SymbolAnalysis>(callerRecovered.Count);
        foreach (var analysis in callerRecovered) {
            cancellationToken.ThrowIfCancellationRequested();
            classified.Add(WithSymbolIsolation(
                analysis,
                () => CandidateClassifier.RevalidateRecovered(analysis, preflight.CurrentImage, preflight.CurrentFunctions, instructionDecoder)));
        }

        symbols = classified.ToImmutable();
        return CreateResult("succeeded", preflight, symbols, stageMilliseconds, previousGraph, currentGraph);
    }

    private static Dictionary<Rva, FunctionMatchResult> BuildFunctionMatches(
        CallGraph previous,
        CallGraph current,
        CancellationToken cancellationToken) {
        var matches = new Dictionary<Rva, FunctionMatchResult>();
        foreach (var function in previous.Functions) {
            cancellationToken.ThrowIfCancellationRequested();
            if (!function.IsSuspect)
                matches.Add(function.Range.Begin, FunctionFingerprintMatcher.Match(function, current));
        }

        return matches;
    }

    private static SymbolAnalysis ApplyStructuralRecovery(
        SymbolAnalysis analysis,
        IReadOnlyDictionary<Rva, FunctionMatchResult> functionMatches,
        PeImage currentImage,
        FunctionIndex currentFunctions,
        IInstructionDecoder decoder) {
        if (analysis.Status is not (SymbolStatus.Missing or SymbolStatus.Ambiguous) ||
            analysis.LocationKind != LocationKind.Function ||
            analysis.PreviousDataRva is not { } previousTarget ||
            !functionMatches.TryGetValue(previousTarget, out var match) ||
            match.Status != SymbolStatus.StructuralRecovered ||
            match.CurrentTarget is not { } currentTarget)
            return analysis;

        var recovered = analysis with {
            Status = SymbolStatus.StructuralRecovered,
            CurrentTarget = currentTarget,
            RecoveryEvidence = [new RecoveryEvidence(
                "StructuralFunction",
                previousTarget,
                currentTarget,
                null,
                null,
                null,
                null,
                match.PreviousFingerprint.Sha256)],
            Diagnostics = analysis.Diagnostics
        };
        return CandidateClassifier.RevalidateRecovered(recovered, currentImage, currentFunctions, decoder);
    }

    private static SymbolAnalysis WithSymbolIsolation(
        SignatureCatalogEntry entry,
        SignatureScanResult previousScan,
        SignatureScanResult currentScan,
        Func<SymbolAnalysis> action) {
        try {
            return action();
        } catch (Exception exception) when (exception is not OperationCanceledException) {
            return AnalysisError(entry, previousScan, currentScan, exception);
        }
    }

    private static SymbolAnalysis WithSymbolIsolation(SymbolAnalysis source, Func<SymbolAnalysis> action) {
        try {
            return action();
        } catch (Exception exception) when (exception is not OperationCanceledException) {
            return source with {
                Status = SymbolStatus.AnalysisError,
                CurrentTarget = null,
                RecoveryEvidence = [],
                SuggestedSignature = null,
                Diagnostics = [.. source.Diagnostics, $"{exception.GetType().Name}: {exception.Message}"]
            };
        }
    }

    private static SymbolAnalysis AnalysisError(
        SignatureCatalogEntry entry,
        SignatureScanResult previousScan,
        SignatureScanResult currentScan,
        Exception exception) => new(
            entry.Signature.GeneratedName,
            entry.Location?.NativeName,
            entry.Location?.Kind,
            entry.Signature,
            entry.Location?.Rva,
            previousScan,
            currentScan,
            SymbolStatus.AnalysisError,
            null,
            [],
            null,
            [$"{exception.GetType().Name}: {exception.Message}"]);

    private static T RunStage<T>(
        string name,
        ConsoleProgressReporter reporter,
        IDictionary<string, long> stageMilliseconds,
        CancellationToken cancellationToken,
        Func<T> operation) {
        cancellationToken.ThrowIfCancellationRequested();
        var stopwatch = Stopwatch.StartNew();
        var result = operation();
        cancellationToken.ThrowIfCancellationRequested();
        stopwatch.Stop();
        var elapsedMilliseconds = stopwatch.ElapsedMilliseconds;
        stageMilliseconds.Add(name, elapsedMilliseconds);
        reporter.CompleteStage(name, stopwatch.Elapsed);
        return result;
    }

    private static PatchAnalysisResult CreateResult(
        string runStatus,
        PreflightState preflight,
        ImmutableArray<SymbolAnalysis> symbols,
        IReadOnlyDictionary<string, long> stageMilliseconds,
        CallGraph? previousGraph = null,
        CallGraph? currentGraph = null) => new(
            runStatus,
            preflight.PreviousImage.Identity,
            preflight.CurrentImage.Identity,
            preflight.Configuration,
            preflight.Data,
            symbols,
            new AnalysisMetrics(stageMilliseconds.ToImmutableSortedDictionary(StringComparer.Ordinal)),
            CreateWorkloadCounts(preflight.Signatures.Length, previousGraph, currentGraph));

    private static ImmutableSortedDictionary<string, long> CreateWorkloadCounts(
        int signatureCount,
        CallGraph? previousGraph,
        CallGraph? currentGraph) => new Dictionary<string, long> {
            ["signatures"] = signatureCount,
            ["previous_functions"] = previousGraph?.Functions.Length ?? 0,
            ["current_functions"] = currentGraph?.Functions.Length ?? 0,
            ["previous_direct_calls"] = previousGraph?.DirectCalls.Length ?? 0,
            ["current_direct_calls"] = currentGraph?.DirectCalls.Length ?? 0
        }.ToImmutableSortedDictionary(StringComparer.Ordinal);

    private static void ValidateTerminalSymbols(
        ImmutableArray<SymbolAnalysis> symbols,
        ImmutableArray<SignatureDefinition> inventory) {
        var inventoryNames = inventory
            .Select(signature => signature.GeneratedName)
            .ToImmutableHashSet(StringComparer.Ordinal);
        var analysisNames = symbols
            .Select(symbol => symbol.GeneratedName)
            .ToImmutableHashSet(StringComparer.Ordinal);
        if (symbols.Length != inventory.Length || inventoryNames.Count != inventory.Length)
            throw new InvalidOperationException("The pipeline did not produce one terminal analysis for every inventory entry.");
        if (!analysisNames.SetEquals(inventoryNames))
            throw new InvalidOperationException("The terminal analysis names do not match the loaded inventory.");

        var analysesByName = symbols.ToDictionary(symbol => symbol.GeneratedName, StringComparer.Ordinal);
        var statusCounts = Enum.GetValues<SymbolStatus>()
            .ToDictionary(
                status => status,
                status => inventory.Count(signature => analysesByName[signature.GeneratedName].Status == status));
        if (symbols.Any(symbol => !Enum.IsDefined(symbol.Status)) ||
            statusCounts.Values.Sum() != inventory.Length)
            throw new InvalidOperationException("The terminal symbol status counts do not sum to the inventory count.");
    }

    private void ValidateDecoderPreflight() {
        var probeRva = new Rva(0);
        var result = instructionDecoder.Decode(new byte[] { 0xC3 }, probeRva);
        if (!result.Success || result.Instruction is not { } instruction ||
            instruction.Rva != probeRva || !instruction.Bytes.SequenceEqual(new byte[] { 0xC3 }) ||
            !string.Equals(instruction.OpcodeKey, "Ret", StringComparison.Ordinal) ||
            instruction.FlowControl != FlowControlKind.Return ||
            instruction.NearBranchTarget is not null || instruction.IpRelativeTarget is not null ||
            !instruction.Constants.IsEmpty)
            throw new InvalidDataException($"The instruction decoder failed its preflight probe: {result.Error ?? "invalid decoded instruction."}");
    }

    private static void TryWriteFailedReport(PatchAnalysisResult result, string outputDirectory) {
        try {
            ReportWriter.Write(result, Path.Combine(outputDirectory, "report.json"));
        } catch (Exception exception) {
            Console.Error.WriteLine($"Could not write failed report: {exception.Message}");
        }
    }

    private static void EnsureReadable(string path, string name) {
        if (!File.Exists(path))
            throw new FileNotFoundException($"The {name} does not exist.", path);
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
    }

    private static void EnsureOutputDoesNotOverlapInput(string outputDirectory, params string[] inputPaths) {
        foreach (var inputPath in inputPaths) {
            if (string.Equals(outputDirectory, inputPath, StringComparison.OrdinalIgnoreCase) ||
                outputDirectory.StartsWith(inputPath + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) ||
                outputDirectory.StartsWith(inputPath + Path.AltDirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("The output directory cannot equal or be nested below an input file path.", nameof(outputDirectory));
        }
    }

    private sealed record PreflightState(
        string PreviousExecutable,
        string CurrentExecutable,
        string DataFile,
        string OutputDirectory,
        PeImage PreviousImage,
        PeImage CurrentImage,
        FunctionIndex PreviousFunctions,
        FunctionIndex CurrentFunctions,
        DataCatalog Data,
        ImmutableArray<SignatureDefinition> Signatures,
        AnalysisConfiguration Configuration);
}
