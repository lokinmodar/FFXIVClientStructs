# Patch Revalidation Pipeline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a standalone C# CLI that compares previous and current FFXIV executables, validates every generated signature, recovers uniquely supported structural and caller matches, and writes deterministic review artifacts without requiring IDA or another reverse-engineering application.

**Architecture:** Replace `FFXIVClientStructs.ResolverTester` with a testable `FFXIVClientStructs.PatchAnalyzer` executable. Keep PE loading, generated-signature inventory, scanning, instruction decoding, control-flow indexing, matching, and artifact writing behind repository-owned interfaces; Iced is confined to one decoder adapter. The required path consumes only two PE files and the previous `ida/data.yml`; IDA, Ghidra, Binary Ninja, Rizin, and game-process access remain outside the implementation.

**Tech Stack:** .NET 10, C# 13, `System.Reflection.PortableExecutable`, Iced 1.21.0, YamlDotNet 16.3.0, System.Text.Json, xUnit v3.

## Global Constraints

- Target `net10.0` and follow the repository's CRLF, UTF-8, four-space C#, file-scoped namespace, nullable, and formatter rules.
- Analyze PE32+ AMD64 files read-only; never launch, attach to, debug, or modify the game.
- Keep both executables local and never commit FFXIV binaries, extracted game bytes, or local analysis reports.
- Use only constructed synthetic PE fixtures in automated tests.
- Inventory every generated `Address`; report unmapped entries as `not_in_data`.
- Report zero, one, and multiple matches; do not reuse the runtime resolver's first-match behavior.
- Store locations internally as RVAs and render preferred-base VAs only at the YAML boundary.
- Keep Iced types inside `IcedInstructionDecoder`; downstream projects depend only on repository-owned decoder records.
- Treat `.pdata` as unwind coverage and candidate ranges, not proof that every byte in a range is code.
- Follow reachable control flow; never linearly classify all `.text` bytes as instructions.
- Accept automatic YAML changes only for `direct_unique`, `structural_recovered`, and `caller_recovered`.
- Never accept a fuzzy similarity score or RVA proximity as evidence by itself. Fuzzy whole-function comparison may rank candidates or map callers, but an accepted recovery requires unique structural identity or convergent direct-edge evidence followed by a unique synthesized signature.
- Preserve YAML comments, ordering, blank lines, and all unrelated text; never overwrite the input YAML.
- Write artifacts atomically and omit full personal filesystem paths from them.
- Use `32` as the per-signature match safety limit, `96` as the maximum synthesized-signature length in bytes, and `4` decoded instructions on each side of a call-site fingerprint. Record these values in the report.
- Do not add Dynamis, ReClass.NET, live-memory access, `AnalysisSnapshot`, `RuntimeObservation`, or structure synchronization to this PoC. They require separate follow-on designs.
- Do not copy Dynamis code or derive an implementation from its AGPL-3.0-or-later source. Any later use of its heuristic concepts must be an independent implementation with repository-owned tests and evidence records.

## Source Map

### Production project

`FFXIVClientStructs.PatchAnalyzer/`

- `Program.cs`: Ctrl+C handling and delegation to the application.
- `FFXIVClientStructs.PatchAnalyzer.csproj`: executable dependencies.
- `Cli/AnalyzerOptions.cs`: immutable command-line options.
- `Cli/CommandLine.cs`: argument parsing and usage errors.
- `Cli/ExitCode.cs`: process exit contract.
- `Analysis/PatchAnalyzerApplication.cs`: preflight and pipeline orchestration.
- `Analysis/AnalysisConfiguration.cs`: recorded limits and version overrides.
- `Analysis/AnalysisMetrics.cs`: nondeterministic elapsed timings kept outside review artifacts.
- `Analysis/SymbolAnalysis.cs`: per-symbol evidence and final status.
- `Analysis/PatchAnalysisResult.cs`: complete in-memory result.
- `Binary/AddressTypes.cs`: RVA, preferred VA, file offset, and source-span value types.
- `Binary/BinaryIdentity.cs`: hash, length, filename, and version source.
- `Binary/PeImage.cs`: immutable PE image and bounded reads.
- `Binary/PeSection.cs`: section metadata and bytes.
- `Binary/FunctionIndex.cs`: parsed x64 runtime-function ranges.
- `Signatures/SignaturePattern.cs`: wildcard pattern parsing and formatting.
- `Signatures/SignatureDefinition.cs`: generated signature snapshot.
- `Signatures/GeneratedSignatureInventory.cs`: one-process snapshot of generated addresses.
- `Signatures/SignatureScanner.cs`: deterministic multi-pattern, multi-match scan.
- `Data/DataCatalog.cs`: semantic `data.yml` model and exact source text.
- `Data/DataSourceMap.cs`: address-token spans in the source text.
- `Data/SignatureCorrelator.cs`: generated-name to YAML-location correlation.
- `Decoding/IInstructionDecoder.cs`: decoder boundary.
- `Decoding/DecodedInstruction.cs`: repository-owned instruction facts.
- `Decoding/IcedInstructionDecoder.cs`: only Iced-dependent source file.
- `Graph/CallGraph.cs`: accepted/suspect functions and direct edges.
- `Graph/CallGraphBuilder.cs`: recursive basic-block traversal.
- `Graph/CallSiteFingerprint.cs`: stable normalized call-site windows.
- `Matching/DirectMatcher.cs`: old-source validation and current direct result.
- `Matching/FunctionFingerprintMatcher.cs`: normalized whole-function identity and diagnostic candidate ranking.
- `Matching/CallerRecoveryMatcher.cs`: one-hop caller/call-site recovery.
- `Matching/SignatureSynthesizer.cs`: shortest unique replacement signature.
- `Matching/CandidateClassifier.cs`: explainable status gates.
- `Output/AnalysisReport.cs`: schema-versioned JSON DTO.
- `Output/ReportWriter.cs`: deterministic JSON serialization.
- `Output/CandidateYamlWriter.cs`: exact accepted-token replacement.
- `Output/AtomicFileWriter.cs`: same-directory temporary write and replace.
- `Output/ConsoleProgressReporter.cs`: operator-only stage durations and progress.

### Test project

`FFXIVClientStructs.PatchAnalyzer.Tests/`

- `FFXIVClientStructs.PatchAnalyzer.Tests.csproj`: xUnit v3 project.
- `Fixtures/SyntheticPeBuilder.cs`: constructed PE32+ AMD64 fixtures.
- `Fixtures/TestImages.cs`: opens owned `PeImage` and function-index contexts from synthetic fixtures.
- `Fixtures/FakeInstructionDecoder.cs`: decoder control for graph unit tests.
- `Cli/CommandLineTests.cs`
- `Binary/PeImageTests.cs`
- `Binary/FunctionIndexTests.cs`
- `Signatures/GeneratedSignatureInventoryTests.cs`
- `Signatures/SignatureScannerTests.cs`
- `Data/SignatureCorrelatorTests.cs`
- `Decoding/IcedInstructionDecoderTests.cs`
- `Graph/CallGraphBuilderTests.cs`
- `Graph/CallSiteFingerprintTests.cs`
- `Matching/DirectMatcherTests.cs`
- `Matching/FunctionFingerprintMatcherTests.cs`
- `Matching/CallerRecoveryMatcherTests.cs`
- `Matching/SignatureSynthesizerTests.cs`
- `Output/ArtifactWriterTests.cs`
- `Integration/PatchAnalyzerApplicationTests.cs`

---

### Task 1: Replace ResolverTester with the CLI and test-project shells

**Files:**
- Rename: `FFXIVClientStructs.ResolverTester/` to `FFXIVClientStructs.PatchAnalyzer/`
- Rename: `FFXIVClientStructs.PatchAnalyzer/FFXIVClientStructs.ResolverTester.csproj` to `FFXIVClientStructs.PatchAnalyzer/FFXIVClientStructs.PatchAnalyzer.csproj`
- Delete: `FFXIVClientStructs.PatchAnalyzer/Data.cs`
- Replace: `FFXIVClientStructs.PatchAnalyzer/Program.cs`
- Create: `FFXIVClientStructs.PatchAnalyzer/Cli/AnalyzerOptions.cs`
- Create: `FFXIVClientStructs.PatchAnalyzer/Cli/CommandLine.cs`
- Create: `FFXIVClientStructs.PatchAnalyzer/Cli/ExitCode.cs`
- Create: `FFXIVClientStructs.PatchAnalyzer.Tests/FFXIVClientStructs.PatchAnalyzer.Tests.csproj`
- Create: `FFXIVClientStructs.PatchAnalyzer.Tests/Cli/CommandLineTests.cs`
- Modify: `FFXIVClientStructs.slnx`

**Interfaces:**
- Produces: `AnalyzerOptions`, `CommandLine.Parse(string[])`, `CommandLineResult`, and `ExitCode`.
- Consumes: no analyzer components yet.

- [ ] **Step 1: Rename the existing project and create the failing CLI tests**

Use PowerShell-native moves, replace the ResolverTester path in `.slnx`, add the PatchAnalyzer test-project path, and create the test project with the same xUnit package versions as `InteropGenerator.Tests`.

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <LangVersion>13</LangVersion>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
    <IsPackable>false</IsPackable>
    <IsTestProject>true</IsTestProject>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Microsoft.NET.Test.Sdk" Version="18.0.1" />
    <PackageReference Include="coverlet.collector" Version="6.0.4" />
    <PackageReference Include="xunit.v3" Version="3.2.2" />
    <PackageReference Include="xunit.runner.visualstudio" Version="3.1.5" />
  </ItemGroup>
  <ItemGroup>
    <ProjectReference Include="..\FFXIVClientStructs.PatchAnalyzer\FFXIVClientStructs.PatchAnalyzer.csproj" />
  </ItemGroup>
</Project>
```

```csharp
[Fact]
public void Parse_CompleteAnalyzeCommand_ReturnsTypedOptions() {
    var result = CommandLine.Parse([
        "analyze",
        "--previous-exe", @"C:\builds\old\ffxiv_dx11.exe",
        "--current-exe", @"C:\builds\new\ffxiv_dx11.exe",
        "--data", @"C:\repo\ida\data.yml",
        "--out", @"C:\repo\artifacts\patch-analysis"
    ]);

    Assert.True(result.IsSuccess);
    Assert.Equal(@"C:\builds\old\ffxiv_dx11.exe", result.Options!.PreviousExecutable);
    Assert.Equal(@"C:\builds\new\ffxiv_dx11.exe", result.Options.CurrentExecutable);
}

[Fact]
public void Parse_MissingRequiredOption_ReturnsUsageError() {
    var result = CommandLine.Parse(["analyze", "--previous-exe", "old.exe"]);

    Assert.False(result.IsSuccess);
    Assert.Contains("--current-exe", result.Error, StringComparison.Ordinal);
}
```

- [ ] **Step 2: Run the focused tests and confirm the red state**

Run:

```powershell
dotnet test .\FFXIVClientStructs.PatchAnalyzer.Tests\FFXIVClientStructs.PatchAnalyzer.Tests.csproj --filter FullyQualifiedName~CommandLineTests
```

Expected: compilation fails because the CLI types do not exist.

- [ ] **Step 3: Implement the typed CLI contract**

Use these exact public records and exit codes:

```csharp
public sealed record AnalyzerOptions(
    string PreviousExecutable,
    string CurrentExecutable,
    string DataFile,
    string OutputDirectory,
    string? PreviousVersion,
    string? CurrentVersion);

public sealed record CommandLineResult(AnalyzerOptions? Options, string? Error) {
    public bool IsSuccess => Options is not null;
}

public enum ExitCode {
    Success = 0,
    InvalidInput = 2,
    FatalAnalysis = 3
}
```

`CommandLine.Parse` must accept only the `analyze` verb, reject duplicate/unknown options, require values after each option, require the four path options, and support the two version overrides. `Program.cs` initially prints usage and returns `InvalidInput` for parsing failures; pipeline delegation is added in Task 13.

- [ ] **Step 4: Run the focused tests and solution build**

```powershell
dotnet test .\FFXIVClientStructs.PatchAnalyzer.Tests\FFXIVClientStructs.PatchAnalyzer.Tests.csproj --filter FullyQualifiedName~CommandLineTests
dotnet build .\FFXIVClientStructs.slnx
```

Expected: CLI tests pass and the renamed project builds.

- [ ] **Step 5: Commit the project transition**

```powershell
git add -A -- .\FFXIVClientStructs.ResolverTester .\FFXIVClientStructs.PatchAnalyzer .\FFXIVClientStructs.PatchAnalyzer.Tests .\FFXIVClientStructs.slnx
git commit -m "refactor: establish patch analyzer projects"
```

---

### Task 2: Add explicit address types, binary identity, and bounded PE loading

**Files:**
- Create: `FFXIVClientStructs.PatchAnalyzer/Binary/AddressTypes.cs`
- Create: `FFXIVClientStructs.PatchAnalyzer/Binary/BinaryIdentity.cs`
- Create: `FFXIVClientStructs.PatchAnalyzer/Binary/PeSection.cs`
- Create: `FFXIVClientStructs.PatchAnalyzer/Binary/PeImage.cs`
- Create: `FFXIVClientStructs.PatchAnalyzer.Tests/Fixtures/SyntheticPeBuilder.cs`
- Create: `FFXIVClientStructs.PatchAnalyzer.Tests/Fixtures/TestImages.cs`
- Create: `FFXIVClientStructs.PatchAnalyzer.Tests/Binary/PeImageTests.cs`

**Interfaces:**
- Produces: `PeImage.Open`, section lookup, bounded RVA reads, identity, and explicit RVA/VA conversions.
- Consumes: filesystem paths from `AnalyzerOptions`.

- [ ] **Step 1: Write synthetic PE and rejection tests**

```csharp
[Fact]
public void Open_Amd64Pe32Plus_ExposesIdentitySectionsAndConversions() {
    using var fixture = SyntheticPeBuilder.Create()
        .WithImageBase(0x140000000)
        .WithSection(".text", 0x1000, [0x90, 0xC3], executable: true)
        .WithAdjacentVersion("2026.06.18.0000.0000")
        .Write();

    var image = PeImage.Open(fixture.ExecutablePath);

    Assert.Equal(0x140000000UL, image.ImageBase);
    Assert.Equal("2026.06.18.0000.0000", image.Identity.GameVersion);
    Assert.True(image.TryRead(new Rva(0x1000), 2, out var bytes));
    Assert.Equal(new byte[] { 0x90, 0xC3 }, bytes.ToArray());
    Assert.Equal(new PreferredVa(0x140001000), image.ToPreferredVa(new Rva(0x1000)));
}

[Theory]
[InlineData(Machine.I386, PEMagic.PE32Plus)]
[InlineData(Machine.Amd64, PEMagic.PE32)]
public void Open_IncompatibleImage_Throws(Machine machine, PEMagic magic) {
    using var fixture = SyntheticPeBuilder.Create().WithHeaders(machine, magic).Write();

    Assert.Throws<InvalidDataException>(() => PeImage.Open(fixture.ExecutablePath));
}
```

- [ ] **Step 2: Run the PE tests and confirm they fail**

```powershell
dotnet test .\FFXIVClientStructs.PatchAnalyzer.Tests\FFXIVClientStructs.PatchAnalyzer.Tests.csproj --filter FullyQualifiedName~PeImageTests
```

Expected: compilation fails on the missing binary types.

- [ ] **Step 3: Implement explicit address and identity records**

```csharp
public readonly record struct Rva(uint Value);
public readonly record struct PreferredVa(ulong Value);
public readonly record struct FileOffset(int Value);
public readonly record struct SourceSpan(int Start, int Length);

public sealed record BinaryIdentity(
    string FileName,
    long Length,
    string Sha256,
    string? GameVersion,
    string VersionSource);
```

`PeImage.Open` must read the file into owned immutable section buffers, dispose `PEReader` before returning, verify PE32+ AMD64, calculate uppercase SHA-256, read adjacent `ffxivgame.ver` when present, expose executable sections by `SectionCharacteristics.MemExecute`, and reject missing/overlapping/out-of-file section ranges. Never retain the caller's full path in `BinaryIdentity`.

```csharp
public sealed class PeImage {
    public BinaryIdentity Identity { get; }
    public ulong ImageBase { get; }
    public int SizeOfImage { get; }
    public Rva ExceptionDirectoryRva { get; }
    public int ExceptionDirectorySize { get; }
    public ImmutableArray<PeSection> Sections { get; }
    public ImmutableArray<PeSection> ExecutableSections { get; }
    public static PeImage Open(string path);
    public bool TryRead(Rva rva, int length, out ReadOnlyMemory<byte> bytes);
    public PreferredVa ToPreferredVa(Rva rva);
    public bool TryToRva(PreferredVa preferredVa, out Rva rva);
}
```

- [ ] **Step 4: Implement the deterministic synthetic PE builder**

The builder writes a DOS header, PE signature, AMD64 COFF header, PE32+ optional header, aligned section headers, section data, and optional exception-directory entry. It returns a disposable fixture directory created under `Path.GetTempPath()` and deletes only that exact directory on dispose.

```csharp
public sealed class SyntheticPeBuilder {
    public static SyntheticPeBuilder Create();
    public SyntheticPeBuilder WithHeaders(Machine machine, PEMagic magic);
    public SyntheticPeBuilder WithImageBase(ulong imageBase);
    public SyntheticPeBuilder WithSection(string name, uint rva, byte[] bytes, bool executable);
    public SyntheticPeBuilder WithExceptionDirectory(uint rva, int size);
    public SyntheticPeBuilder WithAdjacentVersion(string version);
    public SyntheticPeFixture Write();
}
```

`TestImages.WithExecutableBytes(byte[])` must write a temporary PE, open it into the byte-owning `PeImage`, dispose the fixture directory, and return the image.

- [ ] **Step 5: Run focused tests and commit**

```powershell
dotnet test .\FFXIVClientStructs.PatchAnalyzer.Tests\FFXIVClientStructs.PatchAnalyzer.Tests.csproj --filter FullyQualifiedName~PeImageTests
git add .\FFXIVClientStructs.PatchAnalyzer\Binary .\FFXIVClientStructs.PatchAnalyzer.Tests\Binary .\FFXIVClientStructs.PatchAnalyzer.Tests\Fixtures\SyntheticPeBuilder.cs .\FFXIVClientStructs.PatchAnalyzer.Tests\Fixtures\TestImages.cs
git commit -m "feat: load patch analyzer PE inputs"
```

---

### Task 3: Inventory generated signatures and correlate them with exact YAML tokens

**Files:**
- Create: `FFXIVClientStructs.PatchAnalyzer/Signatures/SignaturePattern.cs`
- Create: `FFXIVClientStructs.PatchAnalyzer/Signatures/SignatureDefinition.cs`
- Create: `FFXIVClientStructs.PatchAnalyzer/Signatures/GeneratedSignatureInventory.cs`
- Create: `FFXIVClientStructs.PatchAnalyzer/Data/DataCatalog.cs`
- Create: `FFXIVClientStructs.PatchAnalyzer/Data/DataSourceMap.cs`
- Create: `FFXIVClientStructs.PatchAnalyzer/Data/SignatureCorrelator.cs`
- Create: `FFXIVClientStructs.PatchAnalyzer.Tests/Signatures/GeneratedSignatureInventoryTests.cs`
- Create: `FFXIVClientStructs.PatchAnalyzer.Tests/Data/SignatureCorrelatorTests.cs`

**Interfaces:**
- Produces: immutable signature definitions and `SignatureCatalogEntry` values with exact YAML source spans.
- Consumes: generated `InteropGenerator.Runtime.Address` records and previous image base.

- [ ] **Step 1: Write parser, inventory, and correlation tests**

```csharp
[Fact]
public void Parse_PreservesWildcardMaskAndCanonicalText() {
    var pattern = SignaturePattern.Parse("48 8B ?? E8 ?? ?? ?? ??");

    Assert.Equal("48 8B ?? E8 ?? ?? ?? ??", pattern.ToString());
    Assert.Equal(new byte[] { 0xFF, 0xFF, 0, 0xFF, 0, 0, 0, 0 }, pattern.Mask);
}

[Fact]
public void Correlate_FunctionAndInstance_ReturnsExactAddressSpans() {
    const string yaml = """
                        version: 1
                        globals: {}
                        functions: {}
                        classes:
                          Client::Game::Thing:
                            instances:
                              - ea: 0x142000100 # keep
                            funcs:
                              0x140001020: ctor
                        """;
    var catalog = DataCatalog.Parse(yaml, 0x140000000);
    var definitions = new[] {
        SignatureDefinition.Parse("FFXIVClientStructs.FFXIV.Client.Game.Thing.Ctor", "40 53", []),
        SignatureDefinition.Parse("FFXIVClientStructs.FFXIV.Client.Game.Thing.Instance", "48 8B 05 ?? ?? ?? ??", [3])
    };

    var entries = SignatureCorrelator.Correlate(definitions, catalog);

    Assert.Equal(new Rva(0x1020), entries[0].Location!.Rva);
    Assert.Equal(
        "0x140001020",
        yaml.AsSpan(
            entries[0].Location.SourceSpan.Start,
            entries[0].Location.SourceSpan.Length).ToString());
    Assert.Equal(new Rva(0x2000100), entries[1].Location!.Rva);
}
```

- [ ] **Step 2: Run focused tests and confirm the red state**

```powershell
dotnet test .\FFXIVClientStructs.PatchAnalyzer.Tests\FFXIVClientStructs.PatchAnalyzer.Tests.csproj --filter "FullyQualifiedName~GeneratedSignatureInventoryTests|FullyQualifiedName~SignatureCorrelatorTests"
```

Expected: missing signature and data types.

- [ ] **Step 3: Implement the immutable inventory boundary**

```csharp
public sealed record SignaturePattern(
    ImmutableArray<byte> Bytes,
    ImmutableArray<byte> Mask) {
    public static SignaturePattern Parse(string text);
    public override string ToString();
}

public sealed record SignatureDefinition(
    string GeneratedName,
    string PatternText,
    SignaturePattern Pattern,
    ImmutableArray<ushort> RelativeFollowOffsets) {
    public static SignatureDefinition Parse(
        string generatedName,
        string patternText,
        IEnumerable<ushort> relativeFollowOffsets);
}

public interface ISignatureInventory {
    ImmutableArray<SignatureDefinition> Load();
}

public sealed class GeneratedSignatureInventory : ISignatureInventory {
    public ImmutableArray<SignatureDefinition> Load() {
        FFXIVClientStructs.Interop.Generated.Addresses.Register();
        return Resolver.GetInstance.Addresses
            .Select(address => SignatureDefinition.Parse(
                address.Name,
                address.String,
                address.RelativeFollowOffsets))
            .OrderBy(definition => definition.GeneratedName, StringComparer.Ordinal)
            .ToImmutableArray();
    }
}
```

The CLI calls `Load` once in a fresh process. Tests must compare the snapshot count with `Resolver.GetInstance.Addresses.Count` after registration so no generated address can be silently dropped.

- [ ] **Step 4: Implement semantic YAML parsing and an exact source map**

Use YamlDotNet only for semantic shape. Independently scan source lines with indentation-aware state for `globals`, `functions`, `classes`, `funcs`, `instances`, and `vtbls`; record the character span of each `0x...` token. Correlation rules must:

- strip the exact `FFXIVClientStructs.FFXIV.` prefix;
- translate namespace dots to `::`;
- map `Ctor*` and `Dtor*` by lowercasing the first character;
- map `Instance` to the first instance and `StaticVirtualTable` to the primary vtable;
- return `Missing` for Havok or absent entries instead of skipping them;
- return `Ambiguous` for duplicate native names or duplicate source spans.

```csharp
public enum DataCorrelationStatus { Matched, Missing, Ambiguous, Invalid }
public enum LocationKind { Function, Instance, VirtualTable, Global }
public sealed record DataLocation(
    string NativeName,
    LocationKind Kind,
    PreferredVa PreferredVa,
    Rva Rva,
    SourceSpan SourceSpan);
public sealed class DataCatalog {
    public string SourceText { get; }
    public string Version { get; }
    public SourceSpan VersionSourceSpan { get; }
    public ImmutableArray<DataLocation> Locations { get; }
    public static DataCatalog Parse(string sourceText, ulong previousImageBase);
}
public sealed record SignatureCatalogEntry(
    SignatureDefinition Signature,
    DataCorrelationStatus CorrelationStatus,
    DataLocation? Location,
    string? Diagnostic);

public static class SignatureCorrelator {
    public static ImmutableArray<SignatureCatalogEntry> Correlate(
        IReadOnlyList<SignatureDefinition> signatures,
        DataCatalog catalog);
}
```

- [ ] **Step 5: Run tests and commit**

```powershell
dotnet test .\FFXIVClientStructs.PatchAnalyzer.Tests\FFXIVClientStructs.PatchAnalyzer.Tests.csproj --filter "FullyQualifiedName~GeneratedSignatureInventoryTests|FullyQualifiedName~SignatureCorrelatorTests"
git add .\FFXIVClientStructs.PatchAnalyzer\Signatures .\FFXIVClientStructs.PatchAnalyzer\Data .\FFXIVClientStructs.PatchAnalyzer.Tests\Signatures .\FFXIVClientStructs.PatchAnalyzer.Tests\Data
git commit -m "feat: inventory and correlate generated signatures"
```

---

### Task 4: Build the all-match executable-section signature scanner

**Files:**
- Create: `FFXIVClientStructs.PatchAnalyzer/Signatures/SignatureScanner.cs`
- Create: `FFXIVClientStructs.PatchAnalyzer.Tests/Signatures/SignatureScannerTests.cs`

**Interfaces:**
- Produces: `SignatureScanner.Scan(PeImage, IReadOnlyList<SignatureDefinition>, int)`.
- Consumes: `PeImage` and `SignatureDefinition`.

- [ ] **Step 1: Write zero/one/multiple and relative-follow tests**

```csharp
[Fact]
public void Scan_ReturnsAllMatchesSortedByRva() {
    var image = TestImages.WithExecutableBytes([0xAA, 0xBB, 0x90, 0xAA, 0xBB]);
    var definition = SignatureDefinition.Parse("Test.Match", "AA BB", []);

    var result = SignatureScanner.Scan(image, [definition], 32)[definition.GeneratedName];

    Assert.Equal([new Rva(0x1000), new Rva(0x1003)], result.Matches.Select(match => match.PatternRva));
}

[Fact]
public void Scan_AppliesChainedRel32WithCheckedBounds() {
    var image = TestImages.WithExecutableBytes([
        0xE8, 0x05, 0, 0, 0,
        0x90, 0x90, 0x90, 0x90, 0x90,
        0xE9, 0x01, 0, 0, 0,
        0x90, 0xC3
    ]);
    var definition = SignatureDefinition.Parse("Test.Chain", "E8 ?? ?? ?? ??", [1, 1]);

    var match = Assert.Single(SignatureScanner.Scan(image, [definition], 32)[definition.GeneratedName].Matches);

    Assert.Equal(new Rva(0x1010), match.ResolvedRva);
}
```

- [ ] **Step 2: Run the scanner tests and confirm they fail**

```powershell
dotnet test .\FFXIVClientStructs.PatchAnalyzer.Tests\FFXIVClientStructs.PatchAnalyzer.Tests.csproj --filter FullyQualifiedName~SignatureScannerTests
```

Expected: `SignatureScanner` and scan-result records are missing.

- [ ] **Step 3: Implement anchored multi-pattern scanning**

```csharp
public sealed record SignatureMatch(Rva PatternRva, Rva ResolvedRva);
public sealed record SignatureScanResult(
    ImmutableArray<SignatureMatch> Matches,
    bool Truncated,
    ImmutableArray<string> Diagnostics);
```

For each pattern, select its first non-wildcard byte and remember that byte's pattern offset. Group definitions by that anchor byte, walk every executable section once, derive candidate starts with checked subtraction, compare masked bytes, and stop retaining matches after `maxMatches` while setting `Truncated`. Reject all-wildcard or empty patterns during parsing. Apply relative-follow offsets sequentially with signed `rel32` arithmetic and section/image bounds. Sort results by generated name and pattern RVA after any parallel work.

- [ ] **Step 4: Add boundary and safety-limit cases**

Add tests for a match ending at the final executable byte, a pattern spanning two sections being rejected, an out-of-image relative target producing a diagnostic rather than a match, a wildcard first byte, and 33 matches producing 32 retained matches with `Truncated == true`.

- [ ] **Step 5: Run tests and commit**

```powershell
dotnet test .\FFXIVClientStructs.PatchAnalyzer.Tests\FFXIVClientStructs.PatchAnalyzer.Tests.csproj --filter FullyQualifiedName~SignatureScannerTests
git add .\FFXIVClientStructs.PatchAnalyzer\Signatures\SignatureScanner.cs .\FFXIVClientStructs.PatchAnalyzer.Tests\Signatures\SignatureScannerTests.cs
git commit -m "feat: scan all signature matches"
```

---

### Task 5: Isolate Iced behind the repository decoder interface

**Files:**
- Modify: `FFXIVClientStructs.PatchAnalyzer/FFXIVClientStructs.PatchAnalyzer.csproj`
- Create: `FFXIVClientStructs.PatchAnalyzer/Decoding/IInstructionDecoder.cs`
- Create: `FFXIVClientStructs.PatchAnalyzer/Decoding/DecodedInstruction.cs`
- Create: `FFXIVClientStructs.PatchAnalyzer/Decoding/IcedInstructionDecoder.cs`
- Create: `FFXIVClientStructs.PatchAnalyzer.Tests/Decoding/IcedInstructionDecoderTests.cs`

**Interfaces:**
- Produces: a one-instruction decode API with no Iced public types.
- Consumes: bounded bytes and instruction RVA.

- [ ] **Step 1: Add Iced 1.21.0 and write adapter contract tests**

```csharp
[Fact]
public void Decode_DirectCall_ReportsTargetAndEncodedDisplacement() {
    var decoder = new IcedInstructionDecoder();

    var result = decoder.Decode([0xE8, 0x05, 0, 0, 0], new Rva(0x1000));

    Assert.True(result.Success);
    Assert.Equal(FlowControlKind.DirectCall, result.Instruction!.FlowControl);
    Assert.Equal(new Rva(0x100A), result.Instruction.NearBranchTarget);
    Assert.Contains(result.Instruction.Constants,
        constant => constant.Kind == EncodedConstantKind.BranchDisplacement
                    && constant.Range == new ByteRange(1, 4));
}

[Fact]
public void Decode_RipRelativeLoad_ReportsAbsoluteRvaAndDisplacementRange() {
    var result = new IcedInstructionDecoder().Decode(
        [0x48, 0x8B, 0x05, 0x10, 0, 0, 0],
        new Rva(0x2000));

    Assert.Equal(new Rva(0x2017), result.Instruction!.IpRelativeTarget);
    Assert.Contains(result.Instruction.Constants,
        constant => constant.Kind == EncodedConstantKind.IpRelativeDisplacement);
}
```

- [ ] **Step 2: Run decoder tests and confirm the red state**

```powershell
dotnet test .\FFXIVClientStructs.PatchAnalyzer.Tests\FFXIVClientStructs.PatchAnalyzer.Tests.csproj --filter FullyQualifiedName~IcedInstructionDecoderTests
```

Expected: decoder contract types are missing.

- [ ] **Step 3: Implement repository-owned decoder records**

```csharp
public enum FlowControlKind {
    Next, DirectCall, IndirectCall, ConditionalBranch, DirectBranch,
    IndirectBranch, Return, Interrupt, Exception, Transactional
}
public enum EncodedConstantKind {
    BranchDisplacement, IpRelativeDisplacement, Displacement, Immediate
}
public readonly record struct ByteRange(int Start, int Length);
public sealed record DecodedConstant(
    ByteRange Range,
    EncodedConstantKind Kind,
    ulong UnsignedValue);
public sealed record DecodedInstruction(
    Rva Rva,
    ImmutableArray<byte> Bytes,
    string OpcodeKey,
    FlowControlKind FlowControl,
    Rva? NearBranchTarget,
    Rva? IpRelativeTarget,
    ImmutableArray<DecodedConstant> Constants);
public sealed record DecodeResult(
    bool Success,
    DecodedInstruction? Instruction,
    string? Error);
public interface IInstructionDecoder {
    DecodeResult Decode(ReadOnlySpan<byte> bytes, Rva instructionRva);
}
```

Map Iced `FlowControl`, `NearBranchTarget`, `IsIPRelativeMemoryOperand`, and `GetConstantOffsets`. Build `OpcodeKey` from mnemonic plus repository-owned operand-kind names. Return `Success == false` for `Code.INVALID`, truncated instructions, or targets outside the 32-bit RVA domain.

- [ ] **Step 4: Prove the package does not leak across the boundary**

Add a reflection test that every public property/parameter/return type under `FFXIVClientStructs.PatchAnalyzer.Decoding`, except `IcedInstructionDecoder` itself, has no namespace beginning with `Iced`.

- [ ] **Step 5: Run tests and commit**

```powershell
dotnet test .\FFXIVClientStructs.PatchAnalyzer.Tests\FFXIVClientStructs.PatchAnalyzer.Tests.csproj --filter FullyQualifiedName~IcedInstructionDecoderTests
git add .\FFXIVClientStructs.PatchAnalyzer\FFXIVClientStructs.PatchAnalyzer.csproj .\FFXIVClientStructs.PatchAnalyzer\Decoding .\FFXIVClientStructs.PatchAnalyzer.Tests\Decoding
git commit -m "feat: add isolated x64 instruction decoder"
```

---

### Task 6: Parse and query x64 runtime-function ranges

**Files:**
- Create: `FFXIVClientStructs.PatchAnalyzer/Binary/FunctionIndex.cs`
- Create: `FFXIVClientStructs.PatchAnalyzer.Tests/Binary/FunctionIndexTests.cs`
- Modify: `FFXIVClientStructs.PatchAnalyzer.Tests/Fixtures/SyntheticPeBuilder.cs`
- Modify: `FFXIVClientStructs.PatchAnalyzer.Tests/Fixtures/TestImages.cs`

**Interfaces:**
- Produces: sorted `RuntimeFunctionRange` values and exact/containment lookup.
- Consumes: the PE exception directory, not the entire `.pdata` section by assumption.

- [ ] **Step 1: Write exception-directory and containment tests**

```csharp
[Fact]
public void Build_UsesExceptionDirectoryAndFindsContainingRange() {
    using var fixture = SyntheticPeBuilder.Create()
        .WithSection(".text", 0x1000, new byte[0x80], executable: true)
        .WithRuntimeFunctions(
            new RuntimeFunctionSpec(0x1010, 0x1030, 0x3000),
            new RuntimeFunctionSpec(0x1040, 0x1060, 0x3010))
        .Write();
    var image = PeImage.Open(fixture.ExecutablePath);

    var index = FunctionIndex.Build(image);

    Assert.Equal(new Rva(0x1010), index.FindContaining(new Rva(0x1020))!.Begin);
    Assert.Null(index.FindContaining(new Rva(0x1030)));
}
```

- [ ] **Step 2: Run the focused test and confirm failure**

```powershell
dotnet test .\FFXIVClientStructs.PatchAnalyzer.Tests\FFXIVClientStructs.PatchAnalyzer.Tests.csproj --filter FullyQualifiedName~FunctionIndexTests
```

Expected: `FunctionIndex` and runtime-function fixture support are missing.

- [ ] **Step 3: Implement checked 12-byte `RUNTIME_FUNCTION` parsing**

```csharp
public sealed record RuntimeFunctionRange(Rva Begin, Rva End, Rva UnwindInfo);

public sealed class FunctionIndex {
    public ImmutableArray<RuntimeFunctionRange> Ranges { get; }
    public static FunctionIndex Build(PeImage image);
    public RuntimeFunctionRange? FindByStart(Rva start);
    public RuntimeFunctionRange? FindContaining(Rva rva);
}
```

Read exactly `PEHeader.ExceptionTableDirectory`, require size divisible by 12, reject begin >= end, reject ranges outside executable sections, reject overlaps, and sort by begin RVA. Absence of a range is a supported incomplete state for leaf functions; it is not a fatal PE error.

- [ ] **Step 4: Extend the shared fixture with function contexts**

```csharp
public readonly record struct RuntimeFunctionSpec(uint BeginRva, uint EndRva, uint UnwindRva);
public sealed record TestFunctionContext(PeImage Image, FunctionIndex FunctionIndex);
```

Add `SyntheticPeBuilder.WithRuntimeFunctions(params RuntimeFunctionSpec[])`, which emits sorted 12-byte entries and configures the exception directory. Add `TestImages.Function(uint beginRva, uint endRva)`, which creates a synthetic executable range and returns the opened image plus `FunctionIndex.Build(image)`.

- [ ] **Step 5: Run tests and commit**

```powershell
dotnet test .\FFXIVClientStructs.PatchAnalyzer.Tests\FFXIVClientStructs.PatchAnalyzer.Tests.csproj --filter FullyQualifiedName~FunctionIndexTests
git add .\FFXIVClientStructs.PatchAnalyzer\Binary\FunctionIndex.cs .\FFXIVClientStructs.PatchAnalyzer.Tests\Binary\FunctionIndexTests.cs .\FFXIVClientStructs.PatchAnalyzer.Tests\Fixtures\SyntheticPeBuilder.cs .\FFXIVClientStructs.PatchAnalyzer.Tests\Fixtures\TestImages.cs
git commit -m "feat: index x64 runtime functions"
```

---

### Task 7: Build reachable function graphs and direct call edges

**Files:**
- Create: `FFXIVClientStructs.PatchAnalyzer/Graph/CallGraph.cs`
- Create: `FFXIVClientStructs.PatchAnalyzer/Graph/CallGraphBuilder.cs`
- Create: `FFXIVClientStructs.PatchAnalyzer.Tests/Fixtures/FakeInstructionDecoder.cs`
- Create: `FFXIVClientStructs.PatchAnalyzer.Tests/Graph/CallGraphBuilderTests.cs`

**Interfaces:**
- Produces: accepted/suspect function graphs plus direct call and tail-jump indexes.
- Consumes: `PeImage`, `FunctionIndex`, and `IInstructionDecoder`.

- [ ] **Step 1: Write recursive traversal and embedded-data tests**

```csharp
[Fact]
public void Build_StopsAtIndirectBranchWithoutDecodingEmbeddedTable() {
    var decoder = FakeInstructionDecoder.For([
        Instruction.At(0x1000, 2, FlowControlKind.ConditionalBranch, target: 0x1010),
        Instruction.At(0x1002, 5, FlowControlKind.DirectCall, target: 0x2000),
        Instruction.At(0x1007, 2, FlowControlKind.IndirectBranch),
        Instruction.InvalidAt(0x1009),
        Instruction.At(0x1010, 1, FlowControlKind.Return)
    ]);
    var context = TestImages.Function(0x1000, 0x1020);

    var graph = CallGraphBuilder.Build(context.Image, context.FunctionIndex, decoder);

    var function = Assert.Single(graph.Functions);
    Assert.False(function.IsSuspect);
    Assert.DoesNotContain(new Rva(0x1009), function.ReachableInstructions);
    Assert.Equal(new Rva(0x2000), Assert.Single(graph.DirectCalls).Target);
}

[Fact]
public void Build_ReachableInvalidInstruction_MarksFunctionSuspect() {
    var decoder = FakeInstructionDecoder.For([
        Instruction.At(0x1000, 1, FlowControlKind.Next),
        Instruction.InvalidAt(0x1001)
    ]);
    var context = TestImages.Function(0x1000, 0x1010);

    var function = Assert.Single(
        CallGraphBuilder.Build(context.Image, context.FunctionIndex, decoder).Functions);

    Assert.True(function.IsSuspect);
}
```

Define `Instruction.At` and `Instruction.InvalidAt` as private test factories that return `FakeInstructionSpec`; `FakeInstructionDecoder.For` consumes those specs and returns the exact `DecodeResult` registered for each RVA.

- [ ] **Step 2: Run graph tests and confirm the red state**

```powershell
dotnet test .\FFXIVClientStructs.PatchAnalyzer.Tests\FFXIVClientStructs.PatchAnalyzer.Tests.csproj --filter FullyQualifiedName~CallGraphBuilderTests
```

Expected: graph and fake-decoder types are missing.

- [ ] **Step 3: Implement recursive basic-block traversal**

```csharp
public enum CallEdgeKind { DirectCall, DirectTailJump }
public sealed record CallEdge(
    Rva SourceFunction,
    Rva CallSite,
    Rva Target,
    CallEdgeKind Kind);
public sealed record FunctionGraph(
    RuntimeFunctionRange Range,
    bool IsSuspect,
    ImmutableArray<DecodedInstruction> Instructions,
    ImmutableArray<string> Diagnostics) {
    public ImmutableSortedSet<Rva> ReachableInstructions =>
        Instructions.Select(instruction => instruction.Rva).ToImmutableSortedSet();
}
public sealed class CallGraph {
    public ImmutableArray<FunctionGraph> Functions { get; }
    public ImmutableArray<CallEdge> DirectCalls { get; }
    public ImmutableArray<CallEdge> FindIncoming(Rva target);
}
```

Seed each range begin, decode one instruction at a time, enqueue in-range conditional/direct branch targets, continue the fallthrough for calls and conditional branches, stop on returns/exceptions/interrupts/indirect branches, and record an out-of-range direct unconditional branch as a tail edge. Never follow call targets while decoding the caller. De-duplicate instruction RVAs and sort all output after traversal.

- [ ] **Step 4: Add real-Iced CFG coverage**

Create one synthetic PE whose function contains a direct call, conditional branch, indirect switch branch, and invalid table bytes. Build with `IcedInstructionDecoder` and assert the same accepted graph as the fake-decoder test.

- [ ] **Step 5: Run tests and commit**

```powershell
dotnet test .\FFXIVClientStructs.PatchAnalyzer.Tests\FFXIVClientStructs.PatchAnalyzer.Tests.csproj --filter FullyQualifiedName~CallGraphBuilderTests
git add .\FFXIVClientStructs.PatchAnalyzer\Graph .\FFXIVClientStructs.PatchAnalyzer.Tests\Graph\CallGraphBuilderTests.cs .\FFXIVClientStructs.PatchAnalyzer.Tests\Fixtures\FakeInstructionDecoder.cs
git commit -m "feat: build reachable direct call graphs"
```

---

### Task 8: Classify direct signature results

**Files:**
- Create: `FFXIVClientStructs.PatchAnalyzer/Analysis/AnalysisConfiguration.cs`
- Create: `FFXIVClientStructs.PatchAnalyzer/Analysis/SymbolAnalysis.cs`
- Create: `FFXIVClientStructs.PatchAnalyzer/Matching/DirectMatcher.cs`
- Create: `FFXIVClientStructs.PatchAnalyzer/Matching/CandidateClassifier.cs`
- Create: `FFXIVClientStructs.PatchAnalyzer.Tests/Matching/DirectMatcherTests.cs`

**Interfaces:**
- Produces: one explainable `SymbolAnalysis` for every inventory entry.
- Consumes: catalog correlation and old/current scan results.

- [ ] **Step 1: Write status-table tests**

```csharp
[Theory]
[MemberData(nameof(DirectCases))]
public void Match_ClassifiesRuleConditions(
    DataCorrelationStatus correlation,
    Rva? expectedOld,
    Rva[] oldResults,
    Rva[] currentResults,
    SymbolStatus expectedStatus) {
    var analysis = DirectMatcher.Match(
        TestCatalog.Entry(correlation, expectedOld),
        TestScans.Result(oldResults),
        TestScans.Result(currentResults));

    Assert.Equal(expectedStatus, analysis.Status);
}

public static TheoryData<DataCorrelationStatus, Rva?, Rva[], Rva[], SymbolStatus> DirectCases => new() {
    { DataCorrelationStatus.Missing, null, [], [], SymbolStatus.NotInData },
    { DataCorrelationStatus.Matched, new Rva(0x1000), [new Rva(0x1010)], [], SymbolStatus.StaleSource },
    { DataCorrelationStatus.Matched, new Rva(0x1000), [new Rva(0x1000)], [new Rva(0x2000)], SymbolStatus.DirectUnique },
    { DataCorrelationStatus.Matched, new Rva(0x1000), [new Rva(0x1000)], [], SymbolStatus.Missing },
    { DataCorrelationStatus.Matched, new Rva(0x1000), [new Rva(0x1000)], [new Rva(0x2000), new Rva(0x3000)], SymbolStatus.Ambiguous }
};
```

- [ ] **Step 2: Run focused tests and confirm failure**

```powershell
dotnet test .\FFXIVClientStructs.PatchAnalyzer.Tests\FFXIVClientStructs.PatchAnalyzer.Tests.csproj --filter FullyQualifiedName~DirectMatcherTests
```

Expected: analysis and matcher types are missing.

- [ ] **Step 3: Implement statuses and immutable evidence**

```csharp
public enum SymbolStatus {
    DirectUnique, StructuralRecovered, CallerRecovered, StaleSource, Ambiguous, Missing,
    PossibleInlining, NotInData, Unsupported, AnalysisError
}
public sealed record AnalysisConfiguration(
    int MatchLimit,
    int MaximumSignatureBytes,
    int CallSiteInstructionRadius,
    string? PreviousVersionOverride,
    string? CurrentVersionOverride);
public sealed record RecoveryEvidence(
    string AnchorKind,
    Rva PreviousTarget,
    Rva CurrentTarget,
    Rva? PreviousCaller,
    Rva? PreviousCallSite,
    Rva? CurrentCaller,
    Rva? CurrentCallSite,
    string FingerprintSha256);
public sealed record SignatureProposal(
    string PatternText,
    ImmutableArray<ushort> RelativeFollowOffsets,
    Rva PatternRva,
    Rva ResolvedRva,
    int ByteLength,
    string Source);
public sealed record SymbolAnalysis(
    string GeneratedName,
    string? NativeName,
    LocationKind? LocationKind,
    SignatureDefinition Signature,
    Rva? PreviousDataRva,
    SignatureScanResult PreviousScan,
    SignatureScanResult CurrentScan,
    SymbolStatus Status,
    Rva? CurrentTarget,
    ImmutableArray<RecoveryEvidence> RecoveryEvidence,
    SignatureProposal? SuggestedSignature,
    ImmutableArray<string> Diagnostics);
```

`DirectMatcher` requires exactly one old pattern match, requires its resolved RVA to equal the previous YAML RVA, and grants `DirectUnique` only for exactly one non-truncated current match. Zero/multiple current matches remain eligible for recovery; stale source, unmapped, invalid correlation, or truncated old results do not.

In `DirectMatcherTests.cs`, implement `TestCatalog.Entry(DataCorrelationStatus, Rva?)` as a private factory for `SignatureCatalogEntry` and `TestScans.Result(params Rva[])` as a private factory whose pattern and resolved RVAs are equal. These factories keep each theory row focused on classification rules.

- [ ] **Step 4: Run tests and commit**

```powershell
dotnet test .\FFXIVClientStructs.PatchAnalyzer.Tests\FFXIVClientStructs.PatchAnalyzer.Tests.csproj --filter FullyQualifiedName~DirectMatcherTests
git add .\FFXIVClientStructs.PatchAnalyzer\Analysis .\FFXIVClientStructs.PatchAnalyzer\Matching\DirectMatcher.cs .\FFXIVClientStructs.PatchAnalyzer\Matching\CandidateClassifier.cs .\FFXIVClientStructs.PatchAnalyzer.Tests\Matching\DirectMatcherTests.cs
git commit -m "feat: classify direct patch matches"
```

---

### Task 9: Match normalized whole-function identities

**Files:**
- Create: `FFXIVClientStructs.PatchAnalyzer/Matching/FunctionFingerprintMatcher.cs`
- Create: `FFXIVClientStructs.PatchAnalyzer.Tests/Matching/FunctionFingerprintMatcherTests.cs`

**Interfaces:**
- Produces: deterministic `FunctionFingerprint` values, ranked `FunctionMatchCandidate` diagnostics, and an exact unique target or an explainable non-acceptance status.
- Consumes: accepted old/current `CallGraph` functions and repository-owned decoded instruction/reference records.

- [ ] **Step 1: Write exact, ambiguous, and diagnostic-ranking tests**

```csharp
[Fact]
public void Match_ExactUniqueNormalizedFunction_ReturnsStructuralTarget() {
    var result = FunctionFingerprintMatcher.Match(
        TestFunctions.PreviousTarget(),
        TestFunctions.CurrentExactTargetAndUnrelatedFunctions());

    Assert.Equal(SymbolStatus.StructuralRecovered, result.Status);
    Assert.Equal(new Rva(0x2800), result.CurrentTarget);
}

[Fact]
public void Match_RepeatedSmallFunctionShape_RemainsAmbiguous() {
    var result = FunctionFingerprintMatcher.Match(
        TestFunctions.PreviousNineInstructionWrapper(),
        TestFunctions.CurrentRepeatedWrappers(count: 3));

    Assert.Equal(SymbolStatus.Ambiguous, result.Status);
}

[Fact]
public void Rank_FuzzyCandidates_DoesNotUseRvaDistanceOrGrantRecovery() {
    var result = FunctionFingerprintMatcher.Match(
        TestFunctions.PreviousTarget(),
        TestFunctions.CurrentSimilarTargetsAtSwappedRvas());

    Assert.NotEqual(SymbolStatus.StructuralRecovered, result.Status);
    Assert.All(result.Candidates, candidate => Assert.False(candidate.Exact));
}

[Fact]
public void Create_NormalizesRelocatableOperandsButPreservesMemberOffsets() {
    var oldFunction = TestFunctions.WithRelocatableOperands(
        callTarget: 0x1800,
        ripTarget: 0x9000,
        memberOffset: 0x20);
    var movedFunction = TestFunctions.WithRelocatableOperands(
        callTarget: 0x3800,
        ripTarget: 0xB000,
        memberOffset: 0x20);
    var changedLayout = TestFunctions.WithRelocatableOperands(
        callTarget: 0x3800,
        ripTarget: 0xB000,
        memberOffset: 0x28);

    Assert.Equal(
        FunctionFingerprintMatcher.Create(oldFunction).Sha256,
        FunctionFingerprintMatcher.Create(movedFunction).Sha256);
    Assert.NotEqual(
        FunctionFingerprintMatcher.Create(oldFunction).Sha256,
        FunctionFingerprintMatcher.Create(changedLayout).Sha256);
}

[Fact]
public void Rank_EqualDiagnosticScores_HasDeterministicOrder() {
    var result = FunctionFingerprintMatcher.Match(
        TestFunctions.PreviousTarget(),
        TestFunctions.EqualScoreCandidatesInReverseInputOrder());

    Assert.Equal(
        result.Candidates.OrderBy(candidate => candidate.CurrentTarget),
        result.Candidates);
}
```

- [ ] **Step 2: Run function matcher tests and confirm failure**

```powershell
dotnet test .\FFXIVClientStructs.PatchAnalyzer.Tests\FFXIVClientStructs.PatchAnalyzer.Tests.csproj --filter FullyQualifiedName~FunctionFingerprintMatcherTests
```

Expected: `FunctionFingerprintMatcher`, its records, and the private fixture factory are missing.

- [ ] **Step 3: Implement deterministic whole-function fingerprints**

Build a canonical representation from reachable basic blocks sorted by graph traversal order. Include normalized instruction forms, successor topology, direct-edge kinds, normalized RIP-relative reference categories, and stable non-address scalar constants.

```csharp
public sealed record FunctionFingerprint(
    string Sha256,
    ImmutableArray<string> BasicBlockKeys,
    int InstructionCount,
    int DirectEdgeCount);

public sealed record FunctionMatchCandidate(
    Rva CurrentTarget,
    bool Exact,
    int Rank,
    string FingerprintSha256);

public sealed record FunctionMatchResult(
    SymbolStatus Status,
    Rva? CurrentTarget,
    FunctionFingerprint PreviousFingerprint,
    ImmutableArray<FunctionMatchCandidate> Candidates);
```

Exact identity must be unique across the current executable to produce provisional `StructuralRecovered`. Sequence or graph similarity may produce a deterministic ranked diagnostic list but must not produce `StructuralRecovered`, update candidate YAML, or use RVA distance as a scoring input. Small repeated functions stay `Ambiguous`.

Keep `TestFunctions` as a private factory in `FunctionFingerprintMatcherTests.cs`. It must return real `FunctionGraph` and decoded-instruction records rather than a test-only matcher interface.

- [ ] **Step 4: Run tests and commit**

```powershell
dotnet test .\FFXIVClientStructs.PatchAnalyzer.Tests\FFXIVClientStructs.PatchAnalyzer.Tests.csproj --filter FullyQualifiedName~FunctionFingerprintMatcherTests
git add .\FFXIVClientStructs.PatchAnalyzer\Matching\FunctionFingerprintMatcher.cs .\FFXIVClientStructs.PatchAnalyzer.Tests\Matching\FunctionFingerprintMatcherTests.cs
git commit -m "feat: match normalized function identities"
```

---

### Task 10: Recover targets through caller and call-site evidence

**Files:**
- Create: `FFXIVClientStructs.PatchAnalyzer/Graph/CallSiteFingerprint.cs`
- Create: `FFXIVClientStructs.PatchAnalyzer/Matching/CallerRecoveryMatcher.cs`
- Create: `FFXIVClientStructs.PatchAnalyzer.Tests/Graph/CallSiteFingerprintTests.cs`
- Create: `FFXIVClientStructs.PatchAnalyzer.Tests/Matching/CallerRecoveryMatcherTests.cs`

**Interfaces:**
- Produces: `RecoveryEvidence` and a unique recovered target or an explainable non-acceptance status.
- Consumes: old/current graphs, function-match results from Task 9, decoded instructions, and direct results for signed caller anchors.

- [ ] **Step 1: Write call-site normalization and one-hop recovery tests**

```csharp
[Fact]
public void Create_IgnoresBranchAndRipRelativeDisplacements() {
    var oldWindow = TestInstructions.CallWindow(callDisplacement: 0x10, ripDisplacement: 0x20);
    var newWindow = TestInstructions.CallWindow(callDisplacement: 0x70, ripDisplacement: 0x90);

    Assert.Equal(
        CallSiteFingerprint.Create(oldWindow).Sha256,
        CallSiteFingerprint.Create(newWindow).Sha256);
}

[Fact]
public void Recover_UniqueEquivalentCallSite_ReturnsNewTarget() {
    var result = CallerRecoveryMatcher.Recover(
        TestRecovery.MissingDirectTarget(0x1500),
        TestGraphs.OldIncomingCall(0x1200, 0x1230, 0x1500, fingerprint: "A"),
        TestGraphs.CurrentIncomingCall(0x2200, 0x2230, 0x2800, fingerprint: "A"),
        TestRecovery.NoSignedCallerAnchors());

    Assert.Equal(SymbolStatus.CallerRecovered, result.Status);
    Assert.Equal(new Rva(0x2800), result.CurrentTarget);
}

[Fact]
public void Recover_TwoStructurallyMappedCallersConverge_ReturnsTarget() {
    var result = CallerRecoveryMatcher.Recover(
        TestRecovery.MissingDirectTarget(0x1500),
        TestGraphs.TwoOldCallersOf(0x1500),
        TestGraphs.TwoMappedCurrentCallersOf(0x2800),
        TestRecovery.StructuralCallerMatches());

    Assert.Equal(SymbolStatus.CallerRecovered, result.Status);
    Assert.Equal(new Rva(0x2800), result.CurrentTarget);
    Assert.Equal(2, result.RecoveryEvidence.Length);
}

[Fact]
public void Recover_StructurallyMappedCallersDisagree_IsAmbiguous() {
    var result = CallerRecoveryMatcher.Recover(
        TestRecovery.MissingDirectTarget(0x1500),
        TestGraphs.TwoOldCallersOf(0x1500),
        TestGraphs.MappedCurrentCallersOf(0x2800, 0x2900),
        TestRecovery.StructuralCallerMatches());

    Assert.Equal(SymbolStatus.Ambiguous, result.Status);
}

[Fact]
public void Recover_TrustedOldCallSiteSeedsUnreachableDispatchBlock() {
    var result = CallerRecoveryMatcher.Recover(
        TestRecovery.MissingCallSiteSignature(0x1230, target: 0x1500),
        TestGraphs.DispatchBlockReachableOnlyFromTrustedCallSite(0x1230),
        TestGraphs.UniqueEquivalentDispatchBlock(0x2230, target: 0x2800),
        TestRecovery.NoSignedCallerAnchors());

    Assert.Equal(new Rva(0x2800), result.CurrentTarget);
}
```

- [ ] **Step 2: Run call-site/recovery tests and confirm failure**

```powershell
dotnet test .\FFXIVClientStructs.PatchAnalyzer.Tests\FFXIVClientStructs.PatchAnalyzer.Tests.csproj --filter "FullyQualifiedName~CallSiteFingerprintTests|FullyQualifiedName~CallerRecoveryMatcherTests"
```

Expected: call-site fingerprint and recovery types are missing.

- [ ] **Step 3: Implement deterministic call-site fingerprinting**

Create a window of up to four reachable instructions before and after a direct call within the same function. Hash UTF-8 `OpcodeKey` values plus instruction bytes after zeroing branch displacements, RIP-relative displacements, and image-range pointer immediates; preserve small scalar immediates and non-RIP stack/member displacements.

```csharp
public sealed record CallSiteFingerprint(
    string Sha256,
    ImmutableArray<string> OpcodeKeys,
    int InstructionCount);
```

- [ ] **Step 4: Implement ordered recovery rules**

For a missing or ambiguous direct result:

1. return `Unsupported` without graph recovery when the location kind is not `Function`;
2. gather every old incoming direct call and prefer a caller whose generated signature is `DirectUnique` in both images;
3. otherwise map a caller when Task 9 found its exact unique normalized whole-function identity;
4. retain fuzzy caller rankings for diagnostics only; a fuzzy caller cannot anchor recovery by itself;
5. seed decoding at the trusted old signature call-site when the call lies in a dispatch block not reached from the `.pdata` entry traversal;
6. for a trusted seed, require Task 9 to have exactly mapped the enclosing current function, enumerate leading `E8`/`E9` opcode candidates only inside that range, bounded-decode from each candidate, and treat raw opcode hits only as candidate locations;
7. require one normalized current call-site and follow its direct edge;
8. require all accepted independent anchors to converge on one target;
9. return `Ambiguous` for competing sites, targets, or a merely fuzzy enclosing-function mapping;
10. return `PossibleInlining` when old direct edges exist but no equivalent current direct edge exists;
11. return `Unsupported` when only indirect edges or suspect functions could support the result.

Recovery does not yet grant candidate-YAML eligibility; Task 11 must synthesize and revalidate a unique signature first.

Keep `TestRecovery` and `TestGraphs` as private factories in `CallerRecoveryMatcherTests.cs`. They must return real `SymbolAnalysis`, `CallGraph`, Task 9 function-match results, and signed-caller dictionaries rather than alternate test-only interfaces.

- [ ] **Step 5: Run tests and commit**

```powershell
dotnet test .\FFXIVClientStructs.PatchAnalyzer.Tests\FFXIVClientStructs.PatchAnalyzer.Tests.csproj --filter "FullyQualifiedName~CallSiteFingerprintTests|FullyQualifiedName~CallerRecoveryMatcherTests"
git add .\FFXIVClientStructs.PatchAnalyzer\Graph\CallSiteFingerprint.cs .\FFXIVClientStructs.PatchAnalyzer\Matching\CallerRecoveryMatcher.cs .\FFXIVClientStructs.PatchAnalyzer.Tests\Graph\CallSiteFingerprintTests.cs .\FFXIVClientStructs.PatchAnalyzer.Tests\Matching\CallerRecoveryMatcherTests.cs
git commit -m "feat: recover targets through caller evidence"
```

---

### Task 11: Synthesize and revalidate the shortest unique replacement signature

**Files:**
- Create: `FFXIVClientStructs.PatchAnalyzer/Matching/SignatureSynthesizer.cs`
- Create: `FFXIVClientStructs.PatchAnalyzer.Tests/Matching/SignatureSynthesizerTests.cs`
- Modify: `FFXIVClientStructs.PatchAnalyzer/Matching/CandidateClassifier.cs`

**Interfaces:**
- Produces: a validated `SignatureProposal`.
- Consumes: current PE, decoder, function index, recovered target, recovery call-site, and scanner.

- [ ] **Step 1: Write entry-growth and call-site fallback tests**

```csharp
[Fact]
public void Synthesize_GrowsByWholeInstructionsUntilEntryIsUnique() {
    var context = TestSynthesis.TwoFunctionsSharingFirstInstruction();

    var proposal = context.Synthesizer.Synthesize(
        context.Image,
        new Rva(0x1100),
        recoveryCallSite: null);

    Assert.NotNull(proposal);
    Assert.Equal(new Rva(0x1100), proposal.ResolvedRva);
    Assert.Empty(proposal.RelativeFollowOffsets);
    Assert.True(proposal.ByteLength > context.FirstInstructionLength);
}

[Fact]
public void Synthesize_EntryRemainsAmbiguous_UsesLeadingCallSignature() {
    var context = TestSynthesis.AmbiguousEntryWithUniqueCallSite();

    var proposal = context.Synthesizer.Synthesize(
        context.Image,
        new Rva(0x1800),
        new Rva(0x1240));

    Assert.StartsWith("E8 ", proposal!.PatternText, StringComparison.Ordinal);
    Assert.Equal(new ushort[] { 1 }, proposal.RelativeFollowOffsets);
    Assert.Equal(new Rva(0x1800), proposal.ResolvedRva);
}
```

- [ ] **Step 2: Run synthesizer tests and confirm failure**

```powershell
dotnet test .\FFXIVClientStructs.PatchAnalyzer.Tests\FFXIVClientStructs.PatchAnalyzer.Tests.csproj --filter FullyQualifiedName~SignatureSynthesizerTests
```

Expected: synthesizer and proposal types are missing.

- [ ] **Step 3: Implement instruction-aware pattern creation**

Return the `SignatureProposal` record introduced in Task 8. Start at the recovered function entry and append complete reachable instructions. Replace branch and RIP-relative encoded bytes with `??`; replace an immediate only when its value lies within the PE preferred-image range. After every appended instruction, run `SignatureScanner` and accept only one untruncated match resolving to the recovered target. Stop at 96 bytes. If entry synthesis fails and a direct recovery call-site exists, begin with that `E8`/`E9`, use relative-follow offset `1`, append complete following instructions, and apply the same uniqueness gate.

Implement `TestSynthesis` as a private fixture factory in `SignatureSynthesizerTests.cs`; each context exposes real `PeImage`, `FunctionIndex`, `IInstructionDecoder`, `SignatureScanner`, and `SignatureSynthesizer` instances.

- [ ] **Step 4: Gate recovered statuses on proposal validation**

`CandidateClassifier` may retain the recovered target as diagnostic evidence, but it changes the final status to `StructuralRecovered` or `CallerRecovered` only when the proposal rescans uniquely to that target. Otherwise use `Ambiguous` or `Missing` and leave `SuggestedSignature` null.

- [ ] **Step 5: Run tests and commit**

```powershell
dotnet test .\FFXIVClientStructs.PatchAnalyzer.Tests\FFXIVClientStructs.PatchAnalyzer.Tests.csproj --filter FullyQualifiedName~SignatureSynthesizerTests
git add .\FFXIVClientStructs.PatchAnalyzer\Matching\SignatureSynthesizer.cs .\FFXIVClientStructs.PatchAnalyzer\Matching\CandidateClassifier.cs .\FFXIVClientStructs.PatchAnalyzer.Tests\Matching\SignatureSynthesizerTests.cs
git commit -m "feat: synthesize unique replacement signatures"
```

---

### Task 12: Write deterministic JSON and exact candidate YAML atomically

**Files:**
- Create: `FFXIVClientStructs.PatchAnalyzer/Analysis/PatchAnalysisResult.cs`
- Create: `FFXIVClientStructs.PatchAnalyzer/Analysis/AnalysisMetrics.cs`
- Create: `FFXIVClientStructs.PatchAnalyzer/Output/AnalysisReport.cs`
- Create: `FFXIVClientStructs.PatchAnalyzer/Output/AtomicFileWriter.cs`
- Create: `FFXIVClientStructs.PatchAnalyzer/Output/ConsoleProgressReporter.cs`
- Create: `FFXIVClientStructs.PatchAnalyzer/Output/ReportWriter.cs`
- Create: `FFXIVClientStructs.PatchAnalyzer/Output/CandidateYamlWriter.cs`
- Create: `FFXIVClientStructs.PatchAnalyzer.Tests/Output/ArtifactWriterTests.cs`

**Interfaces:**
- Produces: atomic `report.json`, `data.candidate.yml`, and console-only elapsed timings.
- Consumes: sorted analyses, binary identities, configuration, source YAML, workload counts, and analysis metrics.

- [ ] **Step 1: Write deterministic artifact and preservation tests**

```csharp
[Fact]
public void Write_SameResultTwice_ProducesByteIdenticalArtifacts() {
    var firstResult = TestResults.WithMetrics(
        ("load", 12L),
        ("scan", 34L));
    var secondResult = TestResults.WithMetrics(
        ("load", 91L),
        ("scan", 7L));

    var first = ArtifactWriters.WriteToBytes(firstResult);
    var second = ArtifactWriters.WriteToBytes(secondResult);

    Assert.Equal(first.Report, second.Report);
    Assert.Equal(first.CandidateYaml, second.CandidateYaml);
}

[Fact]
public void CandidateYaml_ReplacesOnlyAcceptedSpansAndPreservesText() {
    const string source = """
                          version: old # keep
                          globals: {}
                          functions: {}
                          classes:
                            A:
                              funcs:
                                0x140001000: One # accepted
                                0x140002000: Two # unresolved
                          """;
    var result = TestResults.OneAcceptedReplacement(source, "0x140001000", "0x140003000");

    var output = CandidateYamlWriter.Render(result);

    Assert.Contains("0x140003000: One # accepted", output, StringComparison.Ordinal);
    Assert.Contains("0x140002000: Two # unresolved", output, StringComparison.Ordinal);
    Assert.DoesNotContain("0x140001000: One", output, StringComparison.Ordinal);
}
```

- [ ] **Step 2: Run artifact tests and confirm failure**

```powershell
dotnet test .\FFXIVClientStructs.PatchAnalyzer.Tests\FFXIVClientStructs.PatchAnalyzer.Tests.csproj --filter FullyQualifiedName~ArtifactWriterTests
```

Expected: report and writer types are missing.

- [ ] **Step 3: Implement schema-versioned sorted report DTOs**

Use schema version `1`. Sort symbols by `GeneratedName`, matches by RVA, evidence by old call-site/current call-site, diagnostics ordinally, and status counts by serialized snake-case name. Serialize enums with `JsonStringEnumConverter(JsonNamingPolicy.SnakeCaseLower)`, UTF-8 without BOM, LF inside artifacts, and one final newline. Include only executable filenames, hashes, sizes, game versions/version sources, configuration, deterministic workload counts, relative artifact names, and symbol evidence.

```csharp
public sealed record AnalysisMetrics(
    ImmutableSortedDictionary<string, long> StageMilliseconds);

public sealed record PatchAnalysisResult(
    string RunStatus,
    BinaryIdentity PreviousBinary,
    BinaryIdentity CurrentBinary,
    AnalysisConfiguration Configuration,
    DataCatalog Data,
    ImmutableArray<SymbolAnalysis> Symbols,
    AnalysisMetrics Metrics,
    ImmutableSortedDictionary<string, long> WorkloadCounts);
```

Production timings vary and `ConsoleProgressReporter` writes them to stderr after each stage. `AnalysisReport` and `ReportWriter` must not expose `AnalysisMetrics`; the test above proves different timings produce identical artifacts. No matching or YAML decision may depend on a duration.

Keep `TestResults` and `ArtifactWriters` as private factories in `ArtifactWriterTests.cs`. `ArtifactWriters.WriteToBytes` must call the production renderers with `MemoryStream` destinations; it must not duplicate serialization logic.

- [ ] **Step 4: Implement exact descending-span YAML replacement**

Render a review-required header, optionally replace the version token only from a sibling version file or explicit override, then apply accepted address replacements from highest `SourceSpan.Start` to lowest. Before each replacement, verify the source slice still equals the expected old token. Refuse duplicate spans, overlapping spans, input/output path equality, or a replacement for a non-accepted status.

- [ ] **Step 5: Implement atomic file writes and failure behavior**

Write a uniquely named temporary file in the destination directory, flush and close it, then `File.Move(temp, final, overwrite: true)`. Delete only that exact temporary file on failure/cancellation. A failed run may write only `report.json` with `runStatus: "failed"`; it never writes candidate YAML.

- [ ] **Step 6: Run tests and commit**

```powershell
dotnet test .\FFXIVClientStructs.PatchAnalyzer.Tests\FFXIVClientStructs.PatchAnalyzer.Tests.csproj --filter FullyQualifiedName~ArtifactWriterTests
git add .\FFXIVClientStructs.PatchAnalyzer\Analysis\PatchAnalysisResult.cs .\FFXIVClientStructs.PatchAnalyzer\Analysis\AnalysisMetrics.cs .\FFXIVClientStructs.PatchAnalyzer\Output .\FFXIVClientStructs.PatchAnalyzer.Tests\Output
git commit -m "feat: write reviewable patch artifacts"
```

---

### Task 13: Orchestrate preflight, analysis, cancellation, and exit codes

**Files:**
- Create: `FFXIVClientStructs.PatchAnalyzer/Analysis/PatchAnalyzerApplication.cs`
- Modify: `FFXIVClientStructs.PatchAnalyzer/Program.cs`
- Create: `FFXIVClientStructs.PatchAnalyzer.Tests/Integration/PatchAnalyzerApplicationTests.cs`

**Interfaces:**
- Produces: the complete `analyze` command.
- Consumes: every component built in Tasks 1–11.

- [ ] **Step 1: Write preflight and minimal end-to-end tests**

```csharp
[Fact]
public async Task RunAsync_IdenticalExecutables_ReturnsInvalidInputWithoutArtifacts() {
    using var fixture = TestPatchPair.SameExecutable();

    var exitCode = await fixture.Application.RunAsync(fixture.Options, CancellationToken.None);

    Assert.Equal(ExitCode.InvalidInput, exitCode);
    Assert.False(File.Exists(Path.Combine(fixture.OutputDirectory, "report.json")));
}

[Fact]
public async Task RunAsync_DirectUnique_WritesReportAndCandidateYaml() {
    using var fixture = TestPatchPair.DirectUnique();

    var exitCode = await fixture.Application.RunAsync(fixture.Options, CancellationToken.None);

    Assert.Equal(ExitCode.Success, exitCode);
    Assert.Contains("\"direct_unique\"", File.ReadAllText(fixture.ReportPath), StringComparison.Ordinal);
    Assert.True(File.Exists(fixture.CandidateYamlPath));
}
```

Implement `TestPatchPair` as a private disposable fixture in the integration test file. It constructs both PEs with `SyntheticPeBuilder`, writes source YAML, supplies a synthetic signature inventory to an internal `PatchAnalyzerApplication` constructor, and deletes only its exact temporary root on dispose.

- [ ] **Step 2: Run integration tests and confirm the red state**

```powershell
dotnet test .\FFXIVClientStructs.PatchAnalyzer.Tests\FFXIVClientStructs.PatchAnalyzer.Tests.csproj --filter FullyQualifiedName~PatchAnalyzerApplicationTests
```

Expected: application orchestration is missing.

- [ ] **Step 3: Implement ordered preflight**

Before creating the output directory or artifacts:

1. resolve full input/output paths;
2. require readable previous/current PE and YAML inputs;
3. reject output equal to or nested over an input file path;
4. load both PE identities and reject equal SHA-256 hashes;
5. parse YAML and verify its version agrees with the previous sibling/override when both exist;
6. build function indexes and decoder preflight;
7. load the generated inventory once.

Return `InvalidInput` and write diagnostics to stderr for any preflight failure.

- [ ] **Step 4: Implement the pipeline and symbol-local isolation**

Run old/current signature scanning, graph construction, direct matching, whole-function matching, caller recovery, synthesis, classification, and output in that order. Catch parser/decoder/matcher exceptions around each symbol and emit `AnalysisError` without stopping independent symbols. Before writing artifacts, require exactly one terminal `SymbolAnalysis` per inventory entry and require the status counts to sum to the inventory count. Catch an invariant failure around the whole pipeline, atomically write a failed report when identities and output are already valid, omit candidate YAML, and return `FatalAnalysis`.

```csharp
public sealed class PatchAnalyzerApplication {
    public PatchAnalyzerApplication(
        ISignatureInventory signatureInventory,
        IInstructionDecoder instructionDecoder);
    public static PatchAnalyzerApplication CreateDefault();
    public Task<ExitCode> RunAsync(
        AnalyzerOptions options,
        CancellationToken cancellationToken);
}
```

`CreateDefault` constructs `GeneratedSignatureInventory` and `IcedInstructionDecoder`; tests inject a synthetic inventory and either the real or fake decoder.

- [ ] **Step 5: Implement Ctrl+C without process or input mutation**

```csharp
using var cancellation = new CancellationTokenSource();
Console.CancelKeyPress += (_, eventArgs) => {
    eventArgs.Cancel = true;
    cancellation.Cancel();
};

var parsed = CommandLine.Parse(args);
if (!parsed.IsSuccess) {
    Console.Error.WriteLine(parsed.Error);
    return (int)ExitCode.InvalidInput;
}

return (int)await PatchAnalyzerApplication.CreateDefault()
    .RunAsync(parsed.Options!, cancellation.Token);
```

Cancellation returns `FatalAnalysis`, leaves inputs untouched, and deletes only the current run's exact temporary artifacts.

- [ ] **Step 6: Run integration tests and commit**

```powershell
dotnet test .\FFXIVClientStructs.PatchAnalyzer.Tests\FFXIVClientStructs.PatchAnalyzer.Tests.csproj --filter FullyQualifiedName~PatchAnalyzerApplicationTests
git add .\FFXIVClientStructs.PatchAnalyzer\Analysis\PatchAnalyzerApplication.cs .\FFXIVClientStructs.PatchAnalyzer\Program.cs .\FFXIVClientStructs.PatchAnalyzer.Tests\Integration
git commit -m "feat: orchestrate patch revalidation"
```

---

### Task 14: Complete synthetic acceptance coverage and the operator runbook

**Files:**
- Modify: `FFXIVClientStructs.PatchAnalyzer.Tests/Integration/PatchAnalyzerApplicationTests.cs`
- Create: `docs/patch-revalidation.md`
- Modify: `README.md`

**Interfaces:**
- Produces: acceptance evidence and a contributor-facing patch-day process.
- Consumes: the finished CLI.

- [ ] **Step 1: Add all required synthetic integration scenarios**

Create independent old/new PE pairs for:

1. original signature remains valid and moves, yielding `direct_unique`;
2. target prologue changes but its normalized whole-function identity is unique, yielding `structural_recovered`;
3. target prologue changes but two structurally mapped callers converge, yielding `caller_recovered`;
4. a repeated small-function identity stays `ambiguous`;
5. two equivalent current anchors yield `ambiguous`;
6. old direct call disappears, yielding `possible_inlining`;
7. old signature conflicts with YAML, yielding `stale_source`;
8. call-site signature resolves through relative-follow offset `1`;
9. comments/order/blank lines survive candidate YAML;
10. two runs with different elapsed timings produce byte-identical JSON/YAML;
11. embedded jump-table bytes remain unreachable while its trusted old signature call-site can seed a bounded block;
12. one symbol's reachable invalid instruction yields `analysis_error` while another symbol completes.

Also add an inventory-accounting assertion to every integration fixture:

```csharp
Assert.Equal(
    fixture.Inventory.Length,
    result.Symbols.Length);
Assert.Equal(
    fixture.Inventory.Length,
    result.Symbols.GroupBy(symbol => symbol.Status).Sum(group => group.Count()));
Assert.Empty(
    fixture.Inventory.Select(item => item.GeneratedName)
        .Except(result.Symbols.Select(symbol => symbol.GeneratedName), StringComparer.Ordinal));
```

- [ ] **Step 2: Run the complete PatchAnalyzer test project**

```powershell
dotnet test .\FFXIVClientStructs.PatchAnalyzer.Tests\FFXIVClientStructs.PatchAnalyzer.Tests.csproj
```

Expected: all PatchAnalyzer tests pass with no skipped acceptance cases.

- [ ] **Step 3: Write the standalone patch-day runbook**

Document:

```powershell
dotnet run --project .\FFXIVClientStructs.PatchAnalyzer -- analyze `
    --previous-exe C:\builds\previous\ffxiv_dx11.exe `
    --current-exe C:\builds\current\ffxiv_dx11.exe `
    --data .\ida\data.yml `
    --out .\artifacts\patch-analysis
```

Explain binary retention/hash capture, version-source checks, every status, review of `structural_recovered` and `caller_recovered` evidence, copying suggested C# signatures only after semantic/ABI inspection, diff review of candidate YAML, `data-validator.js`, build/tests/format/CExporter, report path privacy, and the fact that IDA/Ghidra are optional investigation tools rather than dependencies.

Also state that Dynamis and ReClass.NET are optional manual companions, not PatchAnalyzer inputs. Dynamis observations are live-process heuristics without the binary-identity and provenance contract required for automatic evidence; IPFD and COM probing are outside this workflow. ReClass.NET-generated C# is not ABI-authoritative and may only inform a separately reviewed structure proposal.

- [ ] **Step 4: Run full repository verification**

```powershell
dotnet restore .\FFXIVClientStructs.slnx
dotnet build .\FFXIVClientStructs.slnx --no-restore
dotnet test .\InteropGenerator.Tests\InteropGenerator.Tests.csproj --no-restore
dotnet test .\FFXIVClientStructs.PatchAnalyzer.Tests\FFXIVClientStructs.PatchAnalyzer.Tests.csproj --no-restore
dotnet format .\FFXIVClientStructs.slnx --verify-no-changes
node .\ida\data-validator.js
```

Expected: build succeeds, both test projects pass, formatting reports no changes, and the unchanged repository YAML validates.

- [ ] **Step 5: Run the optional local real-binary smoke test**

Use retained old/current FFXIV executables when both are available. Do not commit the command's output directory. Confirm the report contains hashes, version sources, workload counts, status counts, no full local paths, and no automatic candidate based on suspect functions or ambiguous evidence.

The 2026-07-28 local reference pair is:

- previous SHA-256 `4236E770E673150E85F8D10BEAB2FC4834C82F86AAB8A555A9175439FC906A6D`, corresponding to `ida/data.yml` version `2026.06.18.0000.0000`;
- current SHA-256 `9483706DDCCC700F95DC4F25ECA500B3B5B0B1BDD2B4297FAE3C69C95A9BD964`, with sibling version `2026.07.16.0001.0000`.

With the inventory at design commit time, the expected direct scan is previous `0/2219/3` and current `4/2212/6` for zero/unique/multiple matches. Expected names and aggregate counts are a diagnostic baseline, not a fixed test gate: if the generated inventory changes, the report must explain the inventory delta instead of silently updating these values.

- [ ] **Step 6: Commit runbook and acceptance coverage**

```powershell
git add .\FFXIVClientStructs.PatchAnalyzer.Tests\Integration\PatchAnalyzerApplicationTests.cs .\README.md
git add -f .\docs\patch-revalidation.md
git commit -m "docs: add patch revalidation runbook"
```

---

## Final Review Gate

Before requesting code review:

```powershell
git status --short
git diff upstream/main...HEAD --check
git log --oneline upstream/main..HEAD
```

Confirm:

- the worktree is clean;
- no executable, extracted bytes, report, or candidate YAML is tracked;
- the runtime resolver's behavior is unchanged;
- all accepted candidates have unique scanner evidence;
- no accepted structural candidate relies only on fuzzy similarity or RVA proximity;
- all Iced references remain confined to the adapter and project package reference;
- the CLI operates with no installed IDA, Ghidra, Binary Ninja, Rizin, or debugger;
- no Dynamis, ReClass.NET, live-memory, `AnalysisSnapshot`, or `RuntimeObservation` dependency or implementation was introduced;
- every implementation task is represented by a focused commit.
