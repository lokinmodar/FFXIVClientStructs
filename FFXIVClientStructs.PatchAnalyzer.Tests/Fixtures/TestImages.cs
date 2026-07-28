using FFXIVClientStructs.PatchAnalyzer.Binary;

namespace FFXIVClientStructs.PatchAnalyzer.Tests.Fixtures;

public static class TestImages {
    public static PeImage WithExecutableBytes(byte[] bytes) {
        using var fixture = SyntheticPeBuilder.Create()
            .WithSection(".text", 0x1000, bytes, executable: true)
            .Write();

        return PeImage.Open(fixture.ExecutablePath);
    }
}
