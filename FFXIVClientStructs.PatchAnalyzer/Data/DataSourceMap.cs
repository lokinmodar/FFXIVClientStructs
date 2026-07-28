using System.Collections.Immutable;
using System.Globalization;
using System.Text.RegularExpressions;
using FFXIVClientStructs.PatchAnalyzer.Binary;

namespace FFXIVClientStructs.PatchAnalyzer.Data;

internal sealed class DataSourceMap {
    private static readonly Regex AddressToken = new(@"0x[0-9A-Fa-f]+", RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex Mapping = new(@"^(?<indent>\s*)(?<key>.+?)(?::(?=\s|$))\s*(?<value>.*?)\s*$", RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex EntryAddress = new(@"^(?<indent>\s*)-\s+ea:\s*(?<address>0x[0-9A-Fa-f]+)", RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private DataSourceMap(string version, SourceSpan versionSourceSpan, ImmutableArray<DataLocation> locations) {
        Version = version;
        VersionSourceSpan = versionSourceSpan;
        Locations = locations;
    }

    public string Version { get; }
    public SourceSpan VersionSourceSpan { get; }
    public ImmutableArray<DataLocation> Locations { get; }

    public static DataSourceMap Scan(string sourceText, ulong imageBase) {
        var locations = ImmutableArray.CreateBuilder<DataLocation>();
        var section = string.Empty;
        var className = string.Empty;
        var classSection = string.Empty;
        var version = string.Empty;
        var versionSpan = new SourceSpan(0, 0);
        var position = 0;

        foreach (var rawLine in sourceText.SplitLines()) {
            var line = RemoveComment(rawLine);
            var mapping = Mapping.Match(line);
            var entry = EntryAddress.Match(line);

            if (section == "classes" && !string.IsNullOrEmpty(className) && (classSection == "instances" || classSection == "vtbls") && entry.Success) {
                var address = entry.Groups["address"].Value;
                AddLocation(locations, address, className, classSection == "instances" ? LocationKind.Instance : LocationKind.VirtualTable, position, rawLine, imageBase);
            } else if (mapping.Success) {
                var indent = mapping.Groups["indent"].Length;
                var key = mapping.Groups["key"].Value.Trim();
                var value = mapping.Groups["value"].Value.Trim();

                if (indent == 0) {
                    section = key;
                    className = string.Empty;
                    classSection = string.Empty;
                    if (key == "version") {
                        version = value;
                        var valueStart = rawLine.IndexOf(value, StringComparison.Ordinal);
                        versionSpan = new SourceSpan(position + valueStart, value.Length);
                    }
                } else if (section == "classes" && indent == 2 && string.IsNullOrEmpty(value)) {
                    className = key;
                    classSection = string.Empty;
                } else if (section == "classes" && indent == 4 && (key == "funcs" || key == "instances" || key == "vtbls")) {
                    classSection = key;
                } else if ((section == "globals" || section == "functions") && indent == 2) {
                    AddLocation(locations, key, value, section == "globals" ? LocationKind.Global : LocationKind.Function, position, rawLine, imageBase);
                } else if (section == "classes" && classSection == "funcs" && indent == 6) {
                    AddLocation(locations, key, $"{className}::{value}", LocationKind.Function, position, rawLine, imageBase);
                }
            }

            position += rawLine.Length;
            if (position < sourceText.Length && sourceText[position] == '\r')
                position++;
            if (position < sourceText.Length && sourceText[position] == '\n')
                position++;
        }

        return new DataSourceMap(version, versionSpan, locations.ToImmutable());
    }

    private static void AddLocation(
        ImmutableArray<DataLocation>.Builder locations,
        string addressText,
        string nativeName,
        LocationKind kind,
        int lineStart,
        string rawLine,
        ulong imageBase) {
        var match = AddressToken.Match(rawLine);
        if (!match.Success || !ulong.TryParse(addressText.AsSpan(2), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out var address))
            return;
        if (address < imageBase || address - imageBase > uint.MaxValue)
            return;

        locations.Add(new DataLocation(
            nativeName,
            kind,
            new PreferredVa(address),
            new Rva((uint)(address - imageBase)),
            new SourceSpan(lineStart + match.Index, match.Length)));
    }

    private static string RemoveComment(string line) {
        var comment = line.IndexOf('#');
        return comment < 0 ? line : line[..comment];
    }
}

internal static class SourceTextExtensions {
    public static IEnumerable<string> SplitLines(this string text) {
        var start = 0;
        for (var index = 0; index < text.Length; index++) {
            if (text[index] != '\n')
                continue;

            var length = index > start && text[index - 1] == '\r' ? index - start - 1 : index - start;
            yield return text.Substring(start, length);
            start = index + 1;
        }

        if (start < text.Length)
            yield return text[start..];
    }
}
