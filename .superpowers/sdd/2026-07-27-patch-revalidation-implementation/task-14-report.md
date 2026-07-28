# Task 14 Report

## Scope

- Added the complete synthetic PatchAnalyzer acceptance matrix in `FFXIVClientStructs.PatchAnalyzer.Tests/Integration/PatchAnalyzerApplicationTests.cs`.
- Added `docs/patch-revalidation.md` and linked it from `README.md`.
- Added one minimal supporting PatchAnalyzer change: a function location whose previous or direct-current target is inside a suspect reachable function now terminates as `analysis_error` with the call-graph diagnostic. This was required by the reachable-invalid-instruction acceptance case; the runtime Resolver was not changed.
- No executable, extracted bytes, report, candidate YAML, personal path, live-memory, Dynamis, ReClass.NET, `AnalysisSnapshot`, or `RuntimeObservation` artifact was added.

## Acceptance Coverage

The integration fixture uses only generated synthetic PE files and asserts inventory accounting for every successful pipeline result:

- moved original signature: `direct_unique`;
- unique normalized function: `structural_recovered`;
- converging structural callers: `caller_recovered`;
- repeated small-function identity: `ambiguous`;
- equivalent current anchors: `ambiguous`;
- disappeared direct call: `possible_inlining`;
- old signature/YAML disagreement: `stale_source`;
- rel32 call-site follow offset `1`;
- candidate YAML comments, ordering, and blank lines;
- byte-identical report and candidate YAML across intentionally varied decoding delays;
- unreachable embedded call-site recovery through a trusted bounded seed;
- a reachable invalid instruction isolated to `analysis_error` while another symbol completes.

## TDD Evidence

Red:

- Initial focused test run failed to compile because the new `StructuralRecovered` fixture and result reader had not yet been implemented (`CS0117` and `CS0103`).
- After the fixture harness was added, the integration matrix exposed the missing behavior: `RunAsync_ReachableInvalidInstruction_IsolatesAnalysisError` expected `AnalysisError` but observed `DirectUnique`.

Green:

- `dotnet test .\FFXIVClientStructs.PatchAnalyzer.Tests\FFXIVClientStructs.PatchAnalyzer.Tests.csproj --filter FullyQualifiedName~PatchAnalyzerApplicationTests --no-restore`
  - Passed: 13; failed: 0.
- `dotnet test .\FFXIVClientStructs.PatchAnalyzer.Tests\FFXIVClientStructs.PatchAnalyzer.Tests.csproj`
  - Passed: 134; failed: 0; skipped: 0.

## Repository Verification

- `dotnet restore .\FFXIVClientStructs.slnx`: passed.
- `dotnet build .\FFXIVClientStructs.slnx --no-restore`: passed with 0 errors. The only warnings were the installed .NET 10 preview notice and line-ending warnings from the checkout.
- `dotnet test .\InteropGenerator.Tests\InteropGenerator.Tests.csproj --no-restore`: passed 165 tests.
- `dotnet test .\FFXIVClientStructs.PatchAnalyzer.Tests\FFXIVClientStructs.PatchAnalyzer.Tests.csproj --no-restore`: passed 134 tests.
- `node .\ida\data-validator.js`: passed after `npm.cmd install --no-save --prefix .\ida js-yaml`; `ida/node_modules` is ignored and untracked.
- `git diff --check`: passed.
- `dotnet format .\FFXIVClientStructs.slnx --verify-no-changes`: not clean due four pre-existing unrelated import-order violations:
  - `FFXIVClientStructs.PatchAnalyzer.Tests/Data/SignatureCorrelatorTests.cs`
  - `FFXIVClientStructs.PatchAnalyzer.Tests/Graph/CallSiteFingerprintTests.cs`
  - `FFXIVClientStructs.PatchAnalyzer/Decoding/IcedInstructionDecoder.cs`
  - `FFXIVClientStructs.PatchAnalyzer/Program.cs`

The formatter also identified CRLF as the configured line ending across the checkout. Running the formatter changed unrelated line endings, so those formatter-only changes were restored. `git diff --name-only` contains only Task 14's two C# files and `README.md`; the new docs and this report are ignored until explicitly force-added.

## Optional Smoke Test

The optional real-binary smoke test was not run. The documented local paths `C:\builds\previous\ffxiv_dx11.exe`, `C:\builds\current\ffxiv_dx11.exe`, and `C:\Dante\ffxiv_dx11.exe` are unavailable. No real binary data or output was created.

## Final Review Notes

- The runtime Resolver is unchanged.
- Accepted candidates continue to require unique scanner evidence; structural recovery remains exact-fingerprint based and caller recovery remains evidence based.
- Iced remains confined to its adapter and package reference.
- The CLI has no installed IDA, Ghidra, Binary Ninja, Rizin, debugger, Dynamis, ReClass.NET, or live-memory dependency.
