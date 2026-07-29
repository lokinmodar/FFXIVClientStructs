# Task 12 Report: Deterministic Patch Artifacts

## Scope

Implemented the output/artifact layer in the requested files only:

- `FFXIVClientStructs.PatchAnalyzer/Analysis/AnalysisMetrics.cs`
- `FFXIVClientStructs.PatchAnalyzer/Analysis/PatchAnalysisResult.cs`
- `FFXIVClientStructs.PatchAnalyzer/Output/AnalysisReport.cs`
- `FFXIVClientStructs.PatchAnalyzer/Output/AtomicFileWriter.cs`
- `FFXIVClientStructs.PatchAnalyzer/Output/ConsoleProgressReporter.cs`
- `FFXIVClientStructs.PatchAnalyzer/Output/ReportWriter.cs`
- `FFXIVClientStructs.PatchAnalyzer/Output/CandidateYamlWriter.cs`
- `FFXIVClientStructs.PatchAnalyzer.Tests/Output/ArtifactWriterTests.cs`

No supporting files outside the specified scope were changed.

## Implementation

- Added `PatchAnalysisResult` and `AnalysisMetrics` with the prescribed immutable result shape.
- Added schema-version `1` report DTOs. Report rendering excludes `AnalysisMetrics`, uses sorted symbol, match, evidence, diagnostics, and status-count projections, serializes enums as snake case, emits UTF-8 without BOM, LF JSON, and one final newline.
- Restricted persisted binary data to executable file names, sizes, hashes, game versions, and version sources. Artifact names are relative names only.
- Added review-required candidate YAML rendering that preserves source text outside exact token spans, replaces spans in descending order, validates source slices, and rejects duplicate/overlapping spans or non-accepted replacements. Only `direct_unique`, `structural_recovered`, and `caller_recovered` can replace an address.
- Version replacement is limited to `CurrentVersionOverride` or an identity sourced from `ffxivgame.ver`.
- Added atomic writes using a unique temporary file in the destination directory, flush/close, overwrite move, and cleanup of only that temporary file. Candidate writes reject equal input/output paths and non-succeeded runs.
- Added console-only elapsed stage reporting to stderr.

## TDD Evidence

### Red

Command:

```powershell
dotnet test .\FFXIVClientStructs.PatchAnalyzer.Tests\FFXIVClientStructs.PatchAnalyzer.Tests.csproj --filter FullyQualifiedName~ArtifactWriterTests --no-restore
```

Result: failed as expected before production code existed. `ArtifactWriterTests.cs` reported `CS0234` for the missing `FFXIVClientStructs.PatchAnalyzer.Output` namespace and `CS0246` for missing `PatchAnalysisResult`.

An earlier `--no-build` attempt executed stale binaries and found no matching tests; it was not treated as red evidence. The command above was rerun with compilation enabled to capture the valid failure.

### Green

Focused command above passed after implementation: `5` passed, `0` failed.

Final focused verification:

```powershell
dotnet test .\FFXIVClientStructs.PatchAnalyzer.Tests\FFXIVClientStructs.PatchAnalyzer.Tests.csproj --filter FullyQualifiedName~ArtifactWriterTests --no-restore
```

Result: `5` passed, `0` failed, duration `113 ms`.

Full analyzer-project verification:

```powershell
dotnet test .\FFXIVClientStructs.PatchAnalyzer.Tests\FFXIVClientStructs.PatchAnalyzer.Tests.csproj --no-restore
```

Result: `115` passed, `0` failed, duration `436 ms`.

The test project reports four existing nullable warnings in `FFXIVClientStructs.PatchAnalyzer.Tests/Data/SignatureCorrelatorTests.cs`; this task did not modify that file.

## Self-Review

- Confirmed report DTOs do not expose metrics or local paths.
- Confirmed timing values only flow to `ConsoleProgressReporter` and cannot affect rendered report or candidate YAML bytes.
- Confirmed candidate replacements derive from catalog spans, preserve untouched source text, and apply in descending position order.
- Confirmed failure/cancellation cleanup is scoped to the writer's unique temporary file.
- Confirmed `git diff --check` reported no whitespace errors before staging.

## Fix Round 1

### Findings Addressed

- Candidate YAML rendering now normalizes all line endings to LF and removes trailing LF characters before adding exactly one final LF.
- `CandidateYamlWriter.Write` now reads the declared input path before creating an atomic output file and requires its content to match `result.Data.SourceText` ordinally. Replacements are constructed from that validated live source, so changed input is rejected before candidate output is created.
- Added targeted writer tests for CRLF/no-final-newline normalization, stale input rejection, duplicate spans, overlapping spans, equal input/output paths, and failed-run candidate suppression.

### TDD Evidence

Focused red command:

```powershell
dotnet test .\FFXIVClientStructs.PatchAnalyzer.Tests\FFXIVClientStructs.PatchAnalyzer.Tests.csproj --filter FullyQualifiedName~ArtifactWriterTests --no-restore
```

Result before the production fix: `2` failed and `9` passed. The intended failures were:

- `CandidateYaml_NormalizesCrLfAndAddsOneFinalNewline`: CRLF remained in the rendered candidate.
- `Write_ChangedInputSource_RejectsStaleCatalogAndDoesNotWriteCandidate`: no exception was thrown for changed input content.

Final focused verification used the same command: `11` passed, `0` failed, duration `120 ms`.

Full analyzer-project verification:

```powershell
dotnet test .\FFXIVClientStructs.PatchAnalyzer.Tests\FFXIVClientStructs.PatchAnalyzer.Tests.csproj --no-restore
```

Result: `121` passed, `0` failed, duration `346 ms`.

### Review Notes

- The overlap test constructs an intentionally invalid catalog through the existing private constructor via reflection; this keeps malformed-span coverage test-only and avoids broadening the production data API.
- The analyzer test project still emits four pre-existing nullable warnings in `FFXIVClientStructs.PatchAnalyzer.Tests/Data/SignatureCorrelatorTests.cs`. This fix round does not modify that file.
