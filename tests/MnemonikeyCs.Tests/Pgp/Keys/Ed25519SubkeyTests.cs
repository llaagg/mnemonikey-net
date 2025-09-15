using System;
using Xunit;
using Xunit.Abstractions;
using MnemonikeyCs.Core;
using MnemonikeyCs.Pgp.Keys;

namespace MnemonikeyCs.Tests.Pgp.Keys;

public class Ed25519SubkeyTests : TestBase
{
    public Ed25519SubkeyTests(ITestOutputHelper output) : base(output) { }
    [Fact]
    public void CreateSigningKey_ValidSeed_CreatesSigningSubkey()
    {
        // Arrange
        var seed = Seed.GenerateRandom();
        var creationTime = DateTime.UtcNow;

        // Act
        using var subkey = Ed25519Subkey.CreateSigningKey(seed, creationTime);

        // Assert
        Assert.Equal(SubkeyType.Signing, subkey.SubkeyType);
        Assert.Equal(0, subkey.Index);
        Assert.Equal(KeyUsage.Sign, subkey.Usage);
        Assert.Equal(PgpAlgorithm.Ed25519, subkey.Algorithm);
        Assert.Equal(creationTime, subkey.CreationTime);
    }

    [Fact]
    public void CreateSigningKey_WithCustomIndex_CreatesSigningSubkeyWithIndex()
    {
        // Arrange
        var seed = Seed.GenerateRandom();
        var creationTime = DateTime.UtcNow;
        const ushort index = 5;

        // Act
        using var subkey = Ed25519Subkey.CreateSigningKey(seed, creationTime, index);

        // Assert
        Assert.Equal(SubkeyType.Signing, subkey.SubkeyType);
        Assert.Equal(index, subkey.Index);
        Assert.Equal(KeyUsage.Sign, subkey.Usage);
    }

    [Fact]
    public void CreateAuthenticationKey_ValidSeed_CreatesAuthenticationSubkey()
    {
        // Arrange
        var seed = Seed.GenerateRandom();
        var creationTime = DateTime.UtcNow;

        // Act
        using var subkey = Ed25519Subkey.CreateAuthenticationKey(seed, creationTime);

        // Assert
        Assert.Equal(SubkeyType.Authentication, subkey.SubkeyType);
        Assert.Equal(0, subkey.Index);
        Assert.Equal(KeyUsage.Authenticate, subkey.Usage);
        Assert.Equal(PgpAlgorithm.Ed25519, subkey.Algorithm);
    }

    [Fact]
    public void CreateAuthenticationKey_WithCustomIndex_CreatesAuthenticationSubkeyWithIndex()
    {
        // Arrange
        var seed = Seed.GenerateRandom();
        var creationTime = DateTime.UtcNow;
        const ushort index = 10;

        // Act
        using var subkey = Ed25519Subkey.CreateAuthenticationKey(seed, creationTime, index);

        // Assert
        Assert.Equal(SubkeyType.Authentication, subkey.SubkeyType);
        Assert.Equal(index, subkey.Index);
        Assert.Equal(KeyUsage.Authenticate, subkey.Usage);
    }

    [Fact]
    public void FromPrivateKey_EncryptionType_ThrowsArgumentException()
    {
        // Arrange
        var privateKey = new byte[32];
        Random.Shared.NextBytes(privateKey);
        var creationTime = DateTime.UtcNow;

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => 
            Ed25519Subkey.FromPrivateKey(privateKey, creationTime, SubkeyType.Encryption));
        
        Assert.Contains("Ed25519 keys cannot be used for encryption", exception.Message);
    }

    [Fact]
    public void FromPrivateKey_ValidParameters_CreatesSubkey()
    {
        // Arrange
        var privateKey = new byte[32];
        Random.Shared.NextBytes(privateKey);
        var creationTime = DateTime.UtcNow;

        // Act
        using var subkey = Ed25519Subkey.FromPrivateKey(privateKey, creationTime, SubkeyType.Signing, 3);

        // Assert
        Assert.Equal(SubkeyType.Signing, subkey.SubkeyType);
        Assert.Equal(3, subkey.Index);
        Assert.Equal(KeyUsage.Sign, subkey.Usage);
    }

    [Fact]
    public void DeterministicGeneration_SameParameters_ProducesSameKey()
    {
        // Arrange
        var seedBytes = new byte[16];
        Random.Shared.NextBytes(seedBytes);
        var seed1 = Seed.FromBytes(seedBytes);
        var seed2 = Seed.FromBytes(seedBytes);
        var creationTime = new DateTime(2023, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        const ushort index = 7;

        // Act
        using var key1 = Ed25519Subkey.CreateSigningKey(seed1, creationTime, index);
        using var key2 = Ed25519Subkey.CreateSigningKey(seed2, creationTime, index);

        // Assert
        Assert.Equal(key1.PublicKeyBytes, key2.PublicKeyBytes);
        Assert.Equal(key1.PrivateKeyBytes, key2.PrivateKeyBytes);
        Assert.Equal(key1.Fingerprint, key2.Fingerprint);
        Assert.Equal(key1.KeyId, key2.KeyId);
        Assert.Equal(key1.Index, key2.Index);
        Assert.Equal(key1.SubkeyType, key2.SubkeyType);
    }

    [Fact]
    public void DifferentIndices_ProduceDifferentKeys()
    {
        // Arrange
        var seed = Seed.GenerateRandom();
        var creationTime = DateTime.UtcNow;

        // Act
        using var key1 = Ed25519Subkey.CreateSigningKey(seed, creationTime, 0);
        using var key2 = Ed25519Subkey.CreateSigningKey(seed, creationTime, 1);

        // Assert
        Assert.NotEqual(key1.PublicKeyBytes, key2.PublicKeyBytes);
        Assert.NotEqual(key1.PrivateKeyBytes, key2.PrivateKeyBytes);
        Assert.NotEqual(key1.Fingerprint, key2.Fingerprint);
        Assert.NotEqual(key1.KeyId, key2.KeyId);
    }

    [Fact]
    public void Sign_ValidData_ReturnsSignature()
    {
        // Arrange
        var seed = Seed.GenerateRandom();
        var creationTime = DateTime.UtcNow;
        using var subkey = Ed25519Subkey.CreateSigningKey(seed, creationTime);
        var data = "Test message"u8.ToArray();

        // Act
        var signature = subkey.Sign(data);

        // Assert
        Assert.NotNull(signature);
        Assert.Equal(64, signature.Length);
    }

    [Fact]
    public void ToString_ReturnsFormattedString()
    {
        // Arrange
        var seed = Seed.GenerateRandom();
        var creationTime = DateTime.UtcNow;
        using var subkey = Ed25519Subkey.CreateSigningKey(seed, creationTime, 5);

        // Act
        var result = subkey.ToString();

        // Assert
        Assert.Contains("Ed25519Subkey", result);
        Assert.Contains("Signing", result);
        Assert.Contains("index=5", result);
    }
}