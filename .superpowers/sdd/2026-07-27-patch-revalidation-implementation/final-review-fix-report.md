# Patch Revalidation Final Review Fix Report

## Scope

This final fix wave addresses the four whole-branch review findings without changing runtime Resolver behavior or introducing real-binary dependencies.

## Findings Addressed

### 1. Current preferred image base

- `PatchAnalysisResult` now carries the current PE preferred image base.
- `CandidateYamlWriter` renders accepted current RVAs against that current image base rather than deriving a base from the previous YAML address.
- A synthetic integration fixture uses previous base `0x140000000` and current base `0x150000000` and verifies the candidate address is `0x150001020`.

### 2. Recovery provenance

- Recovery evidence now distinguishes accepted and rejected anchors.
- Whole-function evidence retains the ordered normalized basic-block inputs used to compute the fingerprint.
- Call-site evidence retains the ordered normalized opcode-and-byte inputs used to compute the fingerprint.
- Evidence retains deterministic considered-candidate records with current caller, call-site, target, rank, exactness, fingerprint hash, and rejection reason.
- Caller recovery now preserves evidence when callers disagree, structural caller mapping is ambiguous or fuzzy, equivalent call-sites are absent or competing, enclosing functions are suspect, or trusted-seed opcode candidates are rejected.
- `CandidateClassifier` only uses accepted recovery evidence when selecting call-sites for signature synthesis, so rejected provenance cannot weaken acceptance rules.
- Report projection sorts evidence and considered candidates while preserving fingerprint-input order.

### 3. Report artifact contract

- Top-level report metadata now includes the PatchAnalyzer assembly version and repository Git SHA.
- Per-symbol report data now includes the previous `data.yml` preferred VA as well as its RVA.
- Workload counts now include previous/current executable bytes and previous/current reachable instruction counts, in addition to signatures, functions, and direct graph edges.
- Timing data remains excluded from deterministic artifacts.

### 4. Production match limit

- The application match limit is now `32`.
- A synthetic integration test produces 33 current matches and verifies that the report retains 32, marks the scan truncated, and classifies the symbol as ambiguous.

## TDD Evidence

The focused test command was run after adding the regression tests and before production changes:

```powershell
dotnet test .\FFXIVClientStructs.PatchAnalyzer.Tests\FFXIVClientStructs.PatchAnalyzer.Tests.csproj --filter "FullyQualifiedName~ArtifactWriterTests|FullyQualifiedName~CallerRecoveryMatcherTests|FullyQualifiedName~PatchAnalyzerApplicationTests"
```

The red run failed on the missing report fields, evidence fields/types, and expanded result constructor. After implementation, the same focused selection passed 42 tests. A subsequent full PatchAnalyzer test run passed 138 tests.

## Verification

The required full repository sequence completed successfully:

```text
dotnet restore .\FFXIVClientStructs.slnx
  success

dotnet build .\FFXIVClientStructs.slnx --no-restore
  success, 0 errors

dotnet test .\InteropGenerator.Tests\InteropGenerator.Tests.csproj --no-restore
  165 passed, 0 failed

dotnet test .\FFXIVClientStructs.PatchAnalyzer.Tests\FFXIVClientStructs.PatchAnalyzer.Tests.csproj --no-restore
  138 passed, 0 failed

dotnet format .\FFXIVClientStructs.slnx --verify-no-changes --no-restore
  success

node .\ida\data-validator.js
  success
```

`git diff --check` completed without errors. No executable, extracted bytes, generated analysis artifact, runtime Resolver code, or real-binary fixture was added.

## Concerns

The solution build continues to report four pre-existing nullable warnings in `SignatureCorrelatorTests.cs`; this fix wave does not modify those lines. No new warning or unresolved functional concern was identified.
