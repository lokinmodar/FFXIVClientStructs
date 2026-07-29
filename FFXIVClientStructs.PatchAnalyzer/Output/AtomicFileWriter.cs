namespace FFXIVClientStructs.PatchAnalyzer.Output;

/// <summary>Writes a file through a uniquely named temporary file in its destination directory.</summary>
public static class AtomicFileWriter {
    /// <summary>Writes content to <paramref name="destinationPath" /> atomically.</summary>
    /// <param name="destinationPath">The destination file path.</param>
    /// <param name="write">The operation that writes the temporary file content.</param>
    /// <param name="cancellationToken">A token that cancels the write.</param>
    public static void Write(string destinationPath, Action<Stream> write, CancellationToken cancellationToken = default) {
        ArgumentException.ThrowIfNullOrWhiteSpace(destinationPath);
        ArgumentNullException.ThrowIfNull(write);

        var fullDestination = Path.GetFullPath(destinationPath);
        var directory = Path.GetDirectoryName(fullDestination)!;
        var temporaryPath = Path.Combine(directory, $".{Path.GetFileName(fullDestination)}.{Guid.NewGuid():N}.tmp");

        try {
            cancellationToken.ThrowIfCancellationRequested();
            using (var stream = new FileStream(temporaryPath, FileMode.CreateNew, FileAccess.Write, FileShare.None)) {
                write(stream);
                cancellationToken.ThrowIfCancellationRequested();
                stream.Flush(flushToDisk: true);
            }

            cancellationToken.ThrowIfCancellationRequested();
            File.Move(temporaryPath, fullDestination, overwrite: true);
        } catch {
            if (File.Exists(temporaryPath))
                File.Delete(temporaryPath);
            throw;
        }
    }
}
