using FFXIVClientStructs.PatchAnalyzer.Binary;

namespace FFXIVClientStructs.PatchAnalyzer.Tests.Fixtures;

public static class TestImages {
    public static PeImage WithExecutableBytes(byte[] bytes) {
        using var fixture = SyntheticPeBuilder.Create()
            .WithSection(".text", 0x1000, bytes, executable: true)
            .Write();

        return PeImage.Open(fixture.ExecutablePath);
    }

    public static TestFunctionContext Function(uint beginRva, uint endRva) {
        using var fixture = SyntheticPeBuilder.Create()
            .WithSection(".text", beginRva, new byte[checked((int)(endRva - beginRva))], executable: true)
            .WithRuntimeFunctions(new RuntimeFunctionSpec(beginRva, endRva, 0x3000))
            .Write();

        var image = PeImage.Open(fixture.ExecutablePath);
        return new TestFunctionContext(image, FunctionIndex.Build(image));
    }
}

public sealed record TestFunctionContext(PeImage Image, FunctionIndex FunctionIndex);
