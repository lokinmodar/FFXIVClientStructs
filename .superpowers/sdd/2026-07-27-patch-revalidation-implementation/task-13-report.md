# Task 13 Report: Patch Analysis Application Orchestration

## Scope

Implemented the requested application layer:

- `FFXIVClientStructs.PatchAnalyzer/Analysis/PatchAnalyzerApplication.cs`
- `FFXIVClientStructs.PatchAnalyzer/Program.cs`
- `FFXIVClientStructs.PatchAnalyzer.Tests/Integration/PatchAnalyzerApplicationTests.cs`

No supporting production files were changed.

## Implementation

- Added `PatchAnalyzerApplication` with production defaults (`GeneratedSignatureInventory` and `IcedInstructionDecoder`) plus constructor injection for integration tests.
- Added ordered preflight before output-directory creation: normalized paths, readable inputs, output/input overlap rejection, PE identity validation, identical-hash rejection, YAML parsing/version agreement, function indexes, and one inventory load.
- Orchestrated correlation, scanning, graph construction, direct matching, whole-function matching, structural recovery, caller recovery, recovered-signature revalidation, terminal-result validation, and deterministic artifact writes.
- Isolated per-symbol parser/decoder/matcher failures as `AnalysisError`; invariant or pipeline failures emit an atomic failed `report.json` after valid preflight and omit candidate YAML.
- Added cancellation handling that returns `FatalAnalysis`, does not mutate inputs, and relies on the existing atomic writer's run-local temporary-file cleanup.
- Replaced the CLI success stub with the specified Ctrl+C-aware application invocation.
- Added synthetic-PE integration coverage for identical-binary preflight rejection and a direct unique match that writes both artifacts.

## TDD Evidence

### Red

```powershell
dotnet test .\FFXIVClientStructs.PatchAnalyzer.Tests\FFXIVClientStructs.PatchAnalyzer.Tests.csproj --filter FullyQualifiedName~PatchAnalyzerApplicationTests --no-restore
```

Result: failed as expected before production code existed. `PatchAnalyzerApplicationTests.cs` failed with `CS0246` because `PatchAnalyzerApplication` was missing.

### Green

Focused verification:

```powershell
dotnet test .\FFXIVClientStructs.PatchAnalyzer.Tests\FFXIVClientStructs.PatchAnalyzer.Tests.csproj --filter FullyQualifiedName~PatchAnalyzerApplicationTests --no-restore
```

Result: `2` passed, `0` failed.

Full analyzer-project verification:

```powershell
dotnet test .\FFXIVClientStructs.PatchAnalyzer.Tests\FFXIVClientStructs.PatchAnalyzer.Tests.csproj --no-restore
```

Result: `123` passed, `0` failed.

The commands emit the repository's existing .NET preview SDK notices and nullable warnings in `FFXIVClientStructs.PatchAnalyzer.Tests/Data/SignatureCorrelatorTests.cs`; this task did not modify that file.

## Self-Review

- Confirmed preflight creates neither the output directory nor artifacts before every input check succeeds.
- Confirmed equal SHA-256 identities return `InvalidInput` and do not create `report.json`.
- Confirmed cancellation is not converted into an invalid-input result or failed report.
- Confirmed symbol results are count- and name-validated before successful artifact writes.
- Confirmed failed pipeline paths write only `report.json` through `ReportWriter` and never invoke `CandidateYamlWriter`.
- Confirmed `git diff --check` reported no whitespace errors before staging.
