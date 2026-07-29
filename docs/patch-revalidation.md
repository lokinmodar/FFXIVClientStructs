# Patch Revalidation Runbook

Use PatchAnalyzer to produce review evidence from a retained previous FFXIV executable, the newly delivered executable, and the previous `ida/data.yml`. It is an offline, read-only PE analysis step. Do not use its candidate YAML or suggested signatures without review.

## Prepare Inputs

1. Retain the exact old and new `ffxiv_dx11.exe` files outside the repository. Record their SHA-256 values and retain the adjacent `ffxivgame.ver` files when available.
2. Confirm `ida/data.yml` is the version for the previous executable. PatchAnalyzer records version sources in `report.json`; an adjacent `ffxivgame.ver` is authoritative when present. Use explicit version overrides only when their provenance is documented in review.
3. Keep analysis output outside tracked source directories. Reports include file names, hashes, version sources, workload counts, and status counts, but not full local paths. Treat hashes, binary names, and any surrounding shell history as patch-day evidence rather than content to publish casually.

Run the analysis from the repository root:

```powershell
dotnet run --project .\FFXIVClientStructs.PatchAnalyzer -- analyze `
    --previous-exe C:\builds\previous\ffxiv_dx11.exe `
    --current-exe C:\builds\current\ffxiv_dx11.exe `
    --data .\ida\data.yml `
    --out .\artifacts\patch-analysis
```

Review `artifacts/patch-analysis/report.json` before opening `data.candidate.yml`. Keep both files untracked. The optional local real-binary smoke test is only appropriate after the synthetic PatchAnalyzer tests pass; it is read-only and its output must remain untracked.

## Interpret Results

Every inventory item has exactly one terminal status.

- `direct_unique`: the old signature agrees with YAML and has one current scanner result. Review the new address and proposed YAML diff.
- `structural_recovered`: direct matching failed, but one exact normalized whole-function identity matched and a unique replacement signature was synthesized. Inspect fingerprint evidence and the proposed signature.
- `caller_recovered`: direct matching failed, but exact caller evidence converged and a replacement signature was synthesized. Inspect every caller and call-site evidence item.
- `stale_source`: the old signature does not resolve to the YAML address. Resolve the old-source disagreement before transporting anything.
- `ambiguous`: scanner, structural, or caller evidence has more than one candidate. Do not accept automatically.
- `missing`: no adequate current evidence was found. Investigate manually.
- `possible_inlining`: old direct caller evidence has no equivalent current direct call. Check for inlining, deletion, or a changed dispatch mechanism.
- `not_in_data`: the signature has no corresponding YAML location. It does not produce a YAML replacement.
- `unsupported`: evidence exists but falls outside a supported, trustworthy recovery path. Investigate manually.
- `analysis_error`: decoding or analysis evidence is suspect. Do not accept an automatic candidate.

Only `direct_unique`, `structural_recovered`, and `caller_recovered` may appear as candidate YAML replacements. Accepted structural candidates must have a unique exact normalized identity, not fuzzy similarity or RVA proximity. Accepted caller candidates must have unique scanner evidence for their proposed signature.

For every `structural_recovered` or `caller_recovered` item, inspect the report's recovery evidence, current target, and `suggested_signature`. Copy a suggested C# signature only after separate semantic and ABI review of the native function, including calling convention, parameters, return type, ownership, and the surrounding control flow. A unique byte sequence does not prove a C# declaration is correct.

## Apply And Validate

1. Review `data.candidate.yml` against `ida/data.yml`. Preserve comments, ordering, and unrelated edits; apply only reviewed locations rather than replacing YAML wholesale.
2. Validate the resulting YAML and then validate the repository surfaces changed by the patch:

```powershell
node .\ida\data-validator.js
dotnet restore .\FFXIVClientStructs.slnx
dotnet build .\FFXIVClientStructs.slnx --no-restore
dotnet test .\InteropGenerator.Tests\InteropGenerator.Tests.csproj --no-restore
dotnet test .\FFXIVClientStructs.PatchAnalyzer.Tests\FFXIVClientStructs.PatchAnalyzer.Tests.csproj --no-restore
dotnet format .\FFXIVClientStructs.slnx --verify-no-changes
dotnet run --project .\CExporter\CExporter.csproj -c Release -- --no-write
```

Run CExporter without `--no-write` only when reviewed C# layout changes intentionally require `ida/ffxiv_structs.yml` updates. Check that `ida/errors.txt` is empty. Include report hashes, version sources, workload counts, status counts, accepted evidence, YAML diff, and command results in patch review; never commit executables, extracted bytes, generated reports, or candidate YAML output.

## Optional Companions

IDA and Ghidra are optional investigation tools, not PatchAnalyzer dependencies or inputs. PatchAnalyzer runs without IDA, Ghidra, Binary Ninja, Rizin, or a debugger.

Dynamis and ReClass.NET are optional manual companions, not PatchAnalyzer inputs or dependencies. Dynamis observations are live-process heuristics; they do not provide the binary-identity and provenance contract required for automatic evidence. IPFD and COM probing are outside this workflow. ReClass.NET-generated C# is not ABI-authoritative and may only inform a separately reviewed structure proposal.
