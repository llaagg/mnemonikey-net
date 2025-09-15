using System;
using System.Numerics;
using FluentAssertions;
using MnemonikeyCs.Core;
using Xunit;
using Xunit.Abstractions;

namespace MnemonikeyCs.Tests.Core;

/// <summary>
/// Tests for the Seed class.
/// </summary>
public sealed class SeedTests : TestBase
{
    public SeedTests(ITestOutputHelper output) : base(output)
    {
    }

    [Fact]
    public void GenerateRandom_ShouldCreateValidSeed()
    {
        // Act
        var seed = Seed.GenerateRandom();

        // Assert
        seed.Should().NotBeNull();
        seed.Era.Should().Be(Era.Current);
        
        var bytes = seed.ToBytes();
        bytes.Should().HaveCount(16); // 128 bits = 16 bytes
        bytes.Should().NotBeEquivalentTo(new byte[16]); // Should not be all zeros

        Log($"Generated seed: {seed.ToHex()}");
    }

    [Fact]
    public void GenerateRandom_ShouldCreateDifferentSeeds()
    {
        // Act
        var seed1 = Seed.GenerateRandom();
        var seed2 = Seed.GenerateRandom();

        // Assert
        seed1.Should().NotBeNull();
        seed2.Should().NotBeNull();
        seed1.Should().NotBe(seed2);
        
        seed1.ToHex().Should().NotBe(seed2.ToHex());
        
        Log($"Seed 1: {seed1.ToHex()}");
        Log($"Seed 2: {seed2.ToHex()}");
    }

    [Theory]
    [InlineData("0123456789abcdef0123456789abcdef")]
    [InlineData("ffffffffffffffffffffffffffffffff")]
    [InlineData("00000000000000000000000000000001")]
    public void FromHex_ShouldCreateValidSeed(string hex)
    {
        // Act
        var seed = Seed.FromHex(hex);

        // Assert
        seed.Should().NotBeNull();
        seed.ToHex().Should().Be(hex);
        
        var bytes = seed.ToBytes();
        bytes.Should().HaveCount(16);

        Log($"Created seed from hex '{hex}': {seed}");
    }

    [Theory]
    [InlineData("0x0123456789abcdef0123456789abcdef")]
    [InlineData("0X0123456789abcdef0123456789abcdef")]
    public void FromHex_WithPrefix_ShouldCreateValidSeed(string hexWithPrefix)
    {
        // Act
        var seed = Seed.FromHex(hexWithPrefix);

        // Assert
        seed.Should().NotBeNull();
        seed.ToHex().Should().Be("0123456789abcdef0123456789abcdef");

        Log($"Created seed from hex with prefix '{hexWithPrefix}': {seed}");
    }

    [Theory]
    [InlineData("123456789abcdef0123456789abcdef")] // 31 chars
    [InlineData("0123456789abcdef0123456789abcdef0")] // 33 chars
    [InlineData("")]
    [InlineData("not-hex-at-all")]
    [InlineData("0123456789abcdef0123456789abcdeg")] // Invalid hex char
    public void FromHex_InvalidInput_ShouldThrowException(string invalidHex)
    {
        // Act & Assert
        var act = () => Seed.FromHex(invalidHex);
        act.Should().Throw<ArgumentException>();

        Log($"Correctly rejected invalid hex: '{invalidHex}'");
    }

    [Fact]
    public void FromBytes_ValidBytes_ShouldCreateSeed()
    {
        // Arrange
        var bytes = new byte[16];
        for (int i = 0; i < 16; i++)
        {
            bytes[i] = (byte)(i * 17); // Some pattern
        }

        // Act
        var seed = Seed.FromBytes(bytes);

        // Assert
        seed.Should().NotBeNull();
        seed.ToBytes().Should().BeEquivalentTo(bytes);

        Log($"Created seed from bytes: {seed.ToHex()}");
    }

    [Theory]
    [InlineData(15)] // Too short
    [InlineData(17)] // Too long
    [InlineData(0)]  // Empty
    public void FromBytes_InvalidLength_ShouldThrowException(int length)
    {
        // Arrange
        var bytes = new byte[length];

        // Act & Assert
        var act = () => Seed.FromBytes(bytes);
        act.Should().Throw<ArgumentException>();

        Log($"Correctly rejected {length}-byte array");
    }

    [Fact]
    public void FromBigInteger_ValidValue_ShouldCreateSeed()
    {
        // Arrange
        var value = BigInteger.Parse("123456789012345678901234567890123456");

        // Act
        var seed = Seed.FromBigInteger(value);

        // Assert
        seed.Should().NotBeNull();
        seed.ToBigInteger().Should().Be(value);

        Log($"Created seed from BigInteger: {seed.ToHex()}");
    }

    [Fact]
    public void FromBigInteger_NegativeValue_ShouldThrowException()
    {
        // Arrange
        var negativeValue = new BigInteger(-1);

        // Act & Assert
        var act = () => Seed.FromBigInteger(negativeValue);
        act.Should().Throw<ArgumentOutOfRangeException>();

        Log("Correctly rejected negative BigInteger");
    }

    [Fact]
    public void FromBigInteger_TooLargeValue_ShouldThrowException()
    {
        // Arrange
        var tooLarge = BigInteger.One << 129; // 129 bits

        // Act & Assert
        var act = () => Seed.FromBigInteger(tooLarge);
        act.Should().Throw<ArgumentOutOfRangeException>();

        Log("Correctly rejected too-large BigInteger");
    }

    [Fact]
    public void ToBigInteger_ShouldRoundTrip()
    {
        // Arrange
        var original = BigInteger.Parse("123456789012345678901234567890123456");
        var seed = Seed.FromBigInteger(original);

        // Act
        var result = seed.ToBigInteger();

        // Assert
        result.Should().Be(original);

        Log($"BigInteger round-trip successful: {original}");
    }

    [Fact]
    public void ToBytes_ShouldRoundTrip()
    {
        // Arrange
        var originalBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        var seed = Seed.FromBytes(originalBytes);

        // Act
        var resultBytes = seed.ToBytes();

        // Assert
        resultBytes.Should().BeEquivalentTo(originalBytes);

        Log($"Byte array round-trip successful");
    }

    [Fact]
    public void ToHex_ShouldRoundTrip()
    {
        // Arrange
        var originalHex = "0123456789abcdef0123456789abcdef";
        var seed = Seed.FromHex(originalHex);

        // Act
        var resultHex = seed.ToHex();

        // Assert
        resultHex.Should().Be(originalHex);

        Log($"Hex round-trip successful: {originalHex}");
    }

    [Fact]
    public void CopyTo_ValidSpan_ShouldCopyBytes()
    {
        // Arrange
        var seed = CreateTestSeed("0123456789abcdef0123456789abcdef");
        var destination = new byte[20]; // Larger than needed

        // Act
        seed.CopyTo(destination.AsSpan());

        // Assert
        destination.AsSpan(0, 16).ToArray().Should().BeEquivalentTo(seed.ToBytes());
        destination.AsSpan(16).ToArray().Should().BeEquivalentTo(new byte[4]); // Should be zeros

        Log("CopyTo successful");
    }

    [Fact]
    public void CopyTo_TooSmallSpan_ShouldThrowException()
    {
        // Arrange
        var seed = CreateTestSeed("0123456789abcdef0123456789abcdef");
        var destination = new byte[10]; // Too small

        // Act & Assert
        var act = () => seed.CopyTo(destination.AsSpan());
        act.Should().Throw<ArgumentException>();

        Log("Correctly rejected too-small span");
    }

    [Fact]
    public void Equality_SameSeeds_ShouldBeEqual()
    {
        // Arrange
        var seed1 = CreateTestSeed("0123456789abcdef0123456789abcdef");
        var seed2 = CreateTestSeed("0123456789abcdef0123456789abcdef");

        // Act & Assert
        seed1.Should().Be(seed2);
        (seed1 == seed2).Should().BeTrue();
        (seed1 != seed2).Should().BeFalse();
        seed1.GetHashCode().Should().Be(seed2.GetHashCode());

        Log("Equality check passed for same seeds");
    }

    [Fact]
    public void Equality_DifferentSeeds_ShouldNotBeEqual()
    {
        // Arrange
        var seed1 = CreateTestSeed("0123456789abcdef0123456789abcdef");
        var seed2 = CreateTestSeed("fedcba9876543210fedcba9876543210");

        // Act & Assert
        seed1.Should().NotBe(seed2);
        (seed1 == seed2).Should().BeFalse();
        (seed1 != seed2).Should().BeTrue();

        Log("Equality check passed for different seeds");
    }

    [Fact]
    public void Dispose_ShouldClearSensitiveData()
    {
        // Arrange
        var seed = CreateTestSeed("0123456789abcdef0123456789abcdef");
        var originalBytes = seed.ToBytes();

        // Act
        seed.Dispose();

        // Assert
        var act = () => seed.ToBytes();
        act.Should().Throw<ObjectDisposedException>();

        var actHex = () => seed.ToHex();
        actHex.Should().Throw<ObjectDisposedException>();

        Log("Dispose correctly cleared sensitive data");
    }

    [Fact]
    public void Era_ShouldReturnCurrentEra()
    {
        // Arrange
        var seed = CreateTestSeed("0123456789abcdef0123456789abcdef");

        // Act
        var era = seed.Era;

        // Assert
        era.Should().Be(Era.Current);
        era.Value.Should().Be(0);

        Log($"Era is correctly set to: {era}");
    }

    [Fact]
    public void ToString_ShouldShowTruncatedValue()
    {
        // Arrange
        var seed = CreateTestSeed("0123456789abcdef0123456789abcdef");

        // Act
        var result = seed.ToString();

        // Assert
        result.Should().StartWith("Seed(01234567...)");
        result.Should().NotContain("0123456789abcdef0123456789abcdef"); // Should not show full seed

        Log($"ToString output: {result}");
    }

    [Fact]
    public void ToString_DisposedSeed_ShouldShowDisposed()
    {
        // Arrange
        var seed = CreateTestSeed("0123456789abcdef0123456789abcdef");
        seed.Dispose();

        // Act
        var result = seed.ToString();

        // Assert
        result.Should().Be("Seed(disposed)");

        Log($"Disposed seed toString: {result}");
    }
}