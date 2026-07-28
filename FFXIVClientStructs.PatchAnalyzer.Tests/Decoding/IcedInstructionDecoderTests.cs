using System.Reflection;
using FFXIVClientStructs.PatchAnalyzer.Binary;
using FFXIVClientStructs.PatchAnalyzer.Decoding;
using Xunit;

namespace FFXIVClientStructs.PatchAnalyzer.Tests.Decoding;

public class IcedInstructionDecoderTests {
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

        Assert.True(result.Success);
        Assert.Equal(new Rva(0x2017), result.Instruction!.IpRelativeTarget);
        Assert.Contains(result.Instruction.Constants,
            constant => constant.Kind == EncodedConstantKind.IpRelativeDisplacement
                        && constant.Range == new ByteRange(3, 4));
    }

    [Fact]
    public void Decode_InvalidCode_ReturnsFailure() {
        var result = new IcedInstructionDecoder().Decode([0x0F, 0xFF], new Rva(0x1000));

        Assert.False(result.Success);
        Assert.Null(result.Instruction);
        Assert.NotNull(result.Error);
    }

    [Fact]
    public void Decode_TruncatedInstruction_ReturnsFailure() {
        var result = new IcedInstructionDecoder().Decode([0xE8, 0x05], new Rva(0x1000));

        Assert.False(result.Success);
        Assert.Null(result.Instruction);
        Assert.NotNull(result.Error);
    }

    [Fact]
    public void Decode_TargetOutsideRvaDomain_ReturnsFailure() {
        var result = new IcedInstructionDecoder().Decode([0xE8, 0x00, 0x00, 0x00, 0x80], new Rva(0));

        Assert.False(result.Success);
        Assert.Null(result.Instruction);
        Assert.NotNull(result.Error);
    }

    [Fact]
    public void Decode_OpcodeKey_UsesRepositoryOwnedOperandKindNames() {
        var result = new IcedInstructionDecoder().Decode([0x48, 0x8B, 0x05, 0x10, 0, 0, 0], new Rva(0x2000));

        Assert.Equal("Mov_Register_Memory", result.Instruction!.OpcodeKey);
    }

    [Fact]
    public void PublicDecodingContracts_DoNotExposeIcedTypes() {
        var contractTypes = typeof(IInstructionDecoder).Assembly
            .GetTypes()
            .Where(type => type.IsPublic
                           && type.Namespace == "FFXIVClientStructs.PatchAnalyzer.Decoding"
                           && type != typeof(IcedInstructionDecoder));

        foreach (var type in contractTypes) {
            foreach (var property in type.GetProperties(BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public))
                Assert.False(IsIcedType(property.PropertyType), $"{type.FullName}.{property.Name} exposes {property.PropertyType.FullName}.");

            foreach (var method in type.GetMethods(BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.DeclaredOnly)) {
                Assert.False(IsIcedType(method.ReturnType), $"{type.FullName}.{method.Name} returns {method.ReturnType.FullName}.");
                foreach (var parameter in method.GetParameters())
                    Assert.False(IsIcedType(parameter.ParameterType), $"{type.FullName}.{method.Name} accepts {parameter.ParameterType.FullName}.");
            }
        }
    }

    private static bool IsIcedType(Type type) => type.Namespace?.StartsWith("Iced", StringComparison.Ordinal) == true;
}
