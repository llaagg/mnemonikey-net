using System;
using Xunit;
using Xunit.Abstractions;
using MnemonikeyCs.Core;
using MnemonikeyCs.Pgp.Keys;

namespace MnemonikeyCs.Tests.Pgp.Keys;

public class Curve25519SubkeyTests : TestBase
{
    public Curve25519SubkeyTests(ITestOutputHelper output) : base(output) { }
    [Fact]
    public void CreateEncryptionKey_ValidSeed_CreatesEncryptionSubkey()
    {
        // Arrange
        var seed = Seed.GenerateRandom();
        var creationTime = DateTime.UtcNow;

        // Act
        using var subkey = Curve25519Subkey.CreateEncryptionKey(seed, creationTime);

        // Assert
        Assert.Equal(0, subkey.Index);
        Assert.Equal(KeyUsage.EncryptCommunications | KeyUsage.EncryptStorage, subkey.Usage);
        Assert.Equal(PgpAlgorithm.Curve25519, subkey.Algorithm);
        Assert.Equal(creationTime, subkey.CreationTime);
        Assert.Equal(32, subkey.PublicKeyBytes.Length);
        Assert.Equal(32, subkey.PrivateKeyBytes.Length);
    }

    [Fact]
    public void CreateEncryptionKey_WithCustomIndex_CreatesEncryptionSubkeyWithIndex()
    {
        // Arrange
        var seed = Seed.GenerateRandom();
        var creationTime = DateTime.UtcNow;
        const ushort index = 3;

        // Act
        using var subkey = Curve25519Subkey.CreateEncryptionKey(seed, creationTime, index);

        // Assert
        Assert.Equal(index, subkey.Index);
        Assert.Equal(KeyUsage.EncryptCommunications | KeyUsage.EncryptStorage, subkey.Usage);
    }

    [Fact]
    public void FromPrivateKey_ValidKey_CreatesSubkey()
    {
        // Arrange
        var privateKey = new byte[32];
        Random.Shared.NextBytes(privateKey);
        var creationTime = DateTime.UtcNow;
        const ushort index = 5;

        // Act
        using var subkey = Curve25519Subkey.FromPrivateKey(privateKey, creationTime, index);

        // Assert
        Assert.Equal(index, subkey.Index);
        Assert.Equal(PgpAlgorithm.Curve25519, subkey.Algorithm);
        Assert.Equal(KeyUsage.EncryptCommunications | KeyUsage.EncryptStorage, subkey.Usage);
    }

    [Fact]
    public void FromPrivateKey_InvalidKeySize_ThrowsArgumentException()
    {
        // Arrange
        var invalidKey = new byte[31]; // Wrong size
        var creationTime = DateTime.UtcNow;

        // Act & Assert
        Assert.Throws<ArgumentException>(() => 
            Curve25519Subkey.FromPrivateKey(invalidKey, creationTime));
    }

    [Fact]
    public void Sign_ThrowsInvalidOperationException()
    {
        // Arrange
        var seed = Seed.GenerateRandom();
        var creationTime = DateTime.UtcNow;
        using var subkey = Curve25519Subkey.CreateEncryptionKey(seed, creationTime);
        var data = "Test message"u8.ToArray();

        // Act & Assert
        var exception = Assert.Throws<InvalidOperationException>(() => subkey.Sign(data));
        Assert.Contains("Curve25519 keys cannot be used for signing", exception.Message);
    }


    [Fact]
    public void PerformKeyAgreement_InvalidPublicKeySize_ThrowsArgumentException()
    {
        // Arrange
        var seed = Seed.GenerateRandom();
        var creationTime = DateTime.UtcNow;
        using var subkey = Curve25519Subkey.CreateEncryptionKey(seed, creationTime);
        var invalidPublicKey = new byte[31]; // Wrong size

        // Act & Assert
        Assert.Throws<ArgumentException>(() => 
            subkey.PerformKeyAgreement(invalidPublicKey));
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
        const ushort index = 2;

        // Act
        using var key1 = Curve25519Subkey.CreateEncryptionKey(seed1, creationTime, index);
        using var key2 = Curve25519Subkey.CreateEncryptionKey(seed2, creationTime, index);

        // Assert
        Assert.Equal(key1.PublicKeyBytes, key2.PublicKeyBytes);
        Assert.Equal(key1.PrivateKeyBytes, key2.PrivateKeyBytes);
        Assert.Equal(key1.Index, key2.Index);
    }

    [Fact]
    public void DifferentIndices_ProduceDifferentKeys()
    {
        // Arrange
        var seed = Seed.GenerateRandom();
        var creationTime = DateTime.UtcNow;

        // Act
        using var key1 = Curve25519Subkey.CreateEncryptionKey(seed, creationTime, 0);
        using var key2 = Curve25519Subkey.CreateEncryptionKey(seed, creationTime, 1);

        // Assert
        Assert.NotEqual(key1.PublicKeyBytes, key2.PublicKeyBytes);
        Assert.NotEqual(key1.PrivateKeyBytes, key2.PrivateKeyBytes);
    }

    [Fact]
    public void ComputeFingerprint_ReturnsValidFingerprint()
    {
        // Arrange
        var seed = Seed.GenerateRandom();
        var creationTime = DateTime.UtcNow;
        using var subkey = Curve25519Subkey.CreateEncryptionKey(seed, creationTime);

        // Act
        var fingerprint = subkey.Fingerprint;

        // Assert
        Assert.NotNull(fingerprint);
        Assert.Equal(32, fingerprint.Length); // SHA-256 hash
    }

    [Fact]
    public void KeyId_ReturnsLast8BytesOfFingerprint()
    {
        // Arrange
        var seed = Seed.GenerateRandom();
        var creationTime = DateTime.UtcNow;
        using var subkey = Curve25519Subkey.CreateEncryptionKey(seed, creationTime);

        // Act
        var fingerprint = subkey.Fingerprint;
        var keyId = subkey.KeyId;

        // Assert
        Assert.Equal(8, keyId.Length);
        Assert.Equal(fingerprint[^8..], keyId);
    }

    [Fact]
    public void ToString_ReturnsFormattedString()
    {
        // Arrange
        var seed = Seed.GenerateRandom();
        var creationTime = DateTime.UtcNow;
        using var subkey = Curve25519Subkey.CreateEncryptionKey(seed, creationTime, 7);

        // Act
        var result = subkey.ToString();

        // Assert
        Assert.Contains("Curve25519Subkey", result);
        Assert.Contains("Encryption", result);
        Assert.Contains("index=7", result);
    }
}