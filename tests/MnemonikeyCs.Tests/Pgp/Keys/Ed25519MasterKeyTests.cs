using System;
using Xunit;
using Xunit.Abstractions;
using MnemonikeyCs.Core;
using MnemonikeyCs.Pgp.Keys;

namespace MnemonikeyCs.Tests.Pgp.Keys;

public class Ed25519MasterKeyTests : TestBase
{
    public Ed25519MasterKeyTests(ITestOutputHelper output) : base(output) { }
    [Fact]
    public void FromSeed_ValidSeed_CreatesMasterKey()
    {
        // Arrange
        var seed = Seed.GenerateRandom();
        var creationTime = DateTime.UtcNow;

        // Act
        using var masterKey = Ed25519MasterKey.FromSeed(seed, creationTime);

        // Assert
        Assert.Equal(creationTime, masterKey.CreationTime);
        Assert.Equal(PgpAlgorithm.Ed25519, masterKey.Algorithm);
        Assert.Equal(KeyUsage.Certify | KeyUsage.Sign, masterKey.Usage);
        Assert.Equal(32, masterKey.PublicKeyBytes.Length);
        Assert.Equal(32, masterKey.PrivateKeyBytes.Length);
        Assert.Equal(32, masterKey.Fingerprint.Length);
        Assert.Equal(8, masterKey.KeyId.Length);
    }

    [Fact]
    public void FromSeed_NullSeed_ThrowsArgumentNullException()
    {
        // Arrange
        var creationTime = DateTime.UtcNow;

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => Ed25519MasterKey.FromSeed(null!, creationTime));
    }

    [Fact]
    public void FromPrivateKey_ValidKey_CreatesMasterKey()
    {
        // Arrange
        var privateKey = new byte[32];
        Random.Shared.NextBytes(privateKey);
        var creationTime = DateTime.UtcNow;

        // Act
        using var masterKey = Ed25519MasterKey.FromPrivateKey(privateKey, creationTime);

        // Assert
        Assert.Equal(creationTime, masterKey.CreationTime);
        Assert.Equal(PgpAlgorithm.Ed25519, masterKey.Algorithm);
        Assert.Equal(KeyUsage.Certify | KeyUsage.Sign, masterKey.Usage);
    }

    [Fact]
    public void FromPrivateKey_InvalidKeySize_ThrowsArgumentException()
    {
        // Arrange
        var invalidKey = new byte[31]; // Wrong size
        var creationTime = DateTime.UtcNow;

        // Act & Assert
        Assert.Throws<ArgumentException>(() => Ed25519MasterKey.FromPrivateKey(invalidKey, creationTime));
    }

    [Fact]
    public void CreateSelfCertification_ValidUserId_ReturnsSignature()
    {
        // Arrange
        var seed = Seed.GenerateRandom();
        var creationTime = DateTime.UtcNow;
        using var masterKey = Ed25519MasterKey.FromSeed(seed, creationTime);
        var userId = "Test User <test@example.com>";

        // Act
        var signature = masterKey.CreateSelfCertification(userId);

        // Assert
        Assert.NotNull(signature);
        Assert.Equal(64, signature.Length); // Ed25519 signature is 64 bytes
    }

    [Fact]
    public void CreateSubkeyBinding_ValidSubkey_ReturnsSignature()
    {
        // Arrange
        var seed = Seed.GenerateRandom();
        var creationTime = DateTime.UtcNow;
        using var masterKey = Ed25519MasterKey.FromSeed(seed, creationTime);
        using var subkey = Ed25519Subkey.CreateSigningKey(seed, creationTime);

        // Act
        var signature = masterKey.CreateSubkeyBinding(subkey);

        // Assert
        Assert.NotNull(signature);
        Assert.Equal(64, signature.Length);
    }

    [Fact]
    public void Sign_ValidData_ReturnsSignature()
    {
        // Arrange
        var seed = Seed.GenerateRandom();
        var creationTime = DateTime.UtcNow;
        using var masterKey = Ed25519MasterKey.FromSeed(seed, creationTime);
        var data = "Hello, World!"u8.ToArray();

        // Act
        var signature = masterKey.Sign(data);

        // Assert
        Assert.NotNull(signature);
        Assert.Equal(64, signature.Length);
    }

    [Fact]
    public void DeterministicGeneration_SameSeedAndTime_ProducesSameKey()
    {
        // Arrange
        var seedBytes = new byte[16];
        Random.Shared.NextBytes(seedBytes);
        var seed1 = Seed.FromBytes(seedBytes);
        var seed2 = Seed.FromBytes(seedBytes);
        var creationTime = new DateTime(2023, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        // Act
        using var key1 = Ed25519MasterKey.FromSeed(seed1, creationTime);
        using var key2 = Ed25519MasterKey.FromSeed(seed2, creationTime);

        // Assert
        Assert.Equal(key1.PublicKeyBytes, key2.PublicKeyBytes);
        Assert.Equal(key1.PrivateKeyBytes, key2.PrivateKeyBytes);
        Assert.Equal(key1.Fingerprint, key2.Fingerprint);
        Assert.Equal(key1.KeyId, key2.KeyId);
    }

    [Fact]
    public void Dispose_DisposesResources()
    {
        // Arrange
        var seed = Seed.GenerateRandom();
        var creationTime = DateTime.UtcNow;
        var masterKey = Ed25519MasterKey.FromSeed(seed, creationTime);

        // Act
        masterKey.Dispose();

        // Assert
        Assert.Throws<ObjectDisposedException>(() => masterKey.PublicKeyBytes);
        Assert.Throws<ObjectDisposedException>(() => masterKey.PrivateKeyBytes);
        Assert.Throws<ObjectDisposedException>(() => masterKey.Fingerprint);
        Assert.Throws<ObjectDisposedException>(() => masterKey.KeyId);
    }
}