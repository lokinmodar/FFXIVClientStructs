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

## Fix Round 1

### Findings Addressed

- Added a deterministic decoder preflight probe that requires the injected decoder to decode a one-byte `RET` instruction at RVA zero with a valid non-empty instruction extent. Decoder exceptions and invalid probe results are now preflight failures, so the application returns `InvalidInput` before creating the output directory.
- Strengthened terminal validation to compare the exact set of terminal `GeneratedName` values with the loaded inventory, reject undefined `SymbolStatus` values, and compare aggregated status counts with the independent inventory count.
- Added production-orchestration integration coverage for decoder-preflight rejection and for a post-preflight decoder failure that writes an atomic failed report without candidate YAML.

### TDD Evidence

Focused red command:

```powershell
dotnet test .\FFXIVClientStructs.PatchAnalyzer.Tests\FFXIVClientStructs.PatchAnalyzer.Tests.csproj --filter FullyQualifiedName~PatchAnalyzerApplicationTests --no-restore
```

The first attempt exposed a test-only `ReadOnlySpan<byte>.SequenceEqual` element-type inference error, which was corrected before behavior evaluation. The valid red run then failed as expected: `RunAsync_DecoderPreflightFails_ReturnsInvalidInputWithoutOutputDirectory` expected `InvalidInput` but received `Success`, proving the decoder was not used in preflight.

Final focused verification used the same command: `4` passed, `0` failed, duration `526 ms`.

Full analyzer-project verification:

```powershell
dotnet test .\FFXIVClientStructs.PatchAnalyzer.Tests\FFXIVClientStructs.PatchAnalyzer.Tests.csproj --no-restore
```

Result: `125` passed, `0` failed, duration `426 ms`.

The test project retains its pre-existing nullable warnings in `FFXIVClientStructs.PatchAnalyzer.Tests/Data/SignatureCorrelatorTests.cs` and .NET preview SDK notices. This fix round did not modify either source.

### Review

- The decoder probe runs after PE/index validation and before inventory loading/output-directory creation, preserving the required preflight ordering.
- The graph-failure test uses a decoder that passes the exact preflight probe but throws while decoding an indexed function, which verifies the separate fatal failed-report path through production orchestration.
- Changes remain limited to the requested application, integration tests, and the required report; `Program.cs` did not require a supporting change.

## Fix Round 2

### Findings Addressed

- Tightened the decoder preflight probe to require the exact one-byte `C3` `Ret` decode shape: matching RVA and bytes, `Ret` opcode key, return flow control, no branch or IP-relative target, and no encoded constants.
- Replaced terminal status aggregation derived directly from the result list with an inventory-indexed count across every defined `SymbolStatus`. An undefined status is excluded from that domain and therefore cannot account for the full inventory total.
- Added focused integration coverage for a decoder that claims successful decoding but returns a non-RET shape; the run must return `InvalidInput` before creating the output directory.

### TDD Evidence

Focused red command:

```powershell
dotnet test .\FFXIVClientStructs.PatchAnalyzer.Tests\FFXIVClientStructs.PatchAnalyzer.Tests.csproj --filter FullyQualifiedName~PatchAnalyzerApplicationTests --no-restore
```

Result before the production fix: `RunAsync_DecoderPreflightDecodesNonRet_ReturnsInvalidInputWithoutOutputDirectory` expected `InvalidInput` but received `Success`, proving the preflight accepted a successful non-RET decode.

Final focused verification used the same command: `5` passed, `0` failed, duration `200 ms`.

Full analyzer-project verification:

```powershell
dotnet test .\FFXIVClientStructs.PatchAnalyzer.Tests\FFXIVClientStructs.PatchAnalyzer.Tests.csproj --no-restore
```

Result: `126` passed, `0` failed, duration `623 ms`.

The existing .NET preview SDK notices and nullable warnings in `FFXIVClientStructs.PatchAnalyzer.Tests/Data/SignatureCorrelatorTests.cs` remain outside this fix round's scope.

### Review

- The decoder probe remains in the approved preflight location after PE/index validation and before inventory loading/output creation.
- Exact inventory-name matching and the existing failed-report integration coverage remain unchanged.
- Changes are limited to `PatchAnalyzerApplication`, `PatchAnalyzerApplicationTests`, and this report.
