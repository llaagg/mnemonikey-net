using System;
using System.Linq;
using Xunit;
using Xunit.Abstractions;
using MnemonikeyCs.Core;
using MnemonikeyCs.Pgp;
using MnemonikeyCs.Pgp.Keys;

namespace MnemonikeyCs.Tests.Pgp;

public class KeySetTests : TestBase
{
    public KeySetTests(ITestOutputHelper output) : base(output) { }
    [Fact]
    public void Create_ValidParameters_CreatesCompleteKeySet()
    {
        // Arrange
        var seed = Seed.GenerateRandom();
        var userId = UserId.Create("Test User", "test@example.com");

        // Act
        using var keySet = KeySet.Create(seed, userId);

        // Assert
        Assert.NotNull(keySet.MasterKey);
        Assert.Equal(userId, keySet.PrimaryUserId);
        Assert.Equal(3, keySet.Subkeys.Count); // Encryption, signing, authentication
        Assert.True(keySet.Signatures.Count > 0); // Should have self-cert and binding signatures

        // Verify we have all expected subkey types
        Assert.NotNull(keySet.GetEncryptionKey());
        Assert.NotNull(keySet.GetSigningKey());
        Assert.NotNull(keySet.GetAuthenticationKey());
    }

    [Fact]
    public void Create_CustomIndices_CreatesKeySetWithCustomIndices()
    {
        // Arrange
        var seed = Seed.GenerateRandom();
        var userId = UserId.FromString("Test User");
        const ushort encIndex = 1;
        const ushort sigIndex = 2;
        const ushort authIndex = 3;

        // Act
        using var keySet = KeySet.Create(seed, userId, encIndex, sigIndex, authIndex);

        // Assert
        Assert.Equal(encIndex, keySet.GetEncryptionKey()!.Index);
        Assert.Equal(sigIndex, keySet.GetSigningKey()!.Index);
        Assert.Equal(authIndex, keySet.GetAuthenticationKey()!.Index);
    }

    [Fact]
    public void ExportPublicKeyArmored_ReturnsValidArmoredKey()
    {
        // Arrange
        var seed = Seed.GenerateRandom();
        var userId = UserId.FromString("Test User <test@example.com>");
        using var keySet = KeySet.Create(seed, userId);

        // Act
        var armoredKey = keySet.ExportPublicKeyArmored();

        // Assert
        Assert.NotNull(armoredKey);
        Assert.Contains("-----BEGIN PGP PUBLIC KEY BLOCK-----", armoredKey);
        Assert.Contains("-----END PGP PUBLIC KEY BLOCK-----", armoredKey);
        Assert.Contains("=", armoredKey); // CRC checksum line
    }

    [Fact]
    public void ExportPublicKeyBinary_ReturnsValidBinaryData()
    {
        // Arrange
        var seed = Seed.GenerateRandom();
        var userId = UserId.FromString("Test User");
        using var keySet = KeySet.Create(seed, userId);

        // Act
        var binaryData = keySet.ExportPublicKeyBinary();

        // Assert
        Assert.NotNull(binaryData);
        Assert.True(binaryData.Length > 0);
        
        // Check for packet headers (new packet format)
        Assert.Contains(binaryData, b => (b & 0xC0) == 0xC0);
    }

    [Fact]
    public void ExportPrivateKeyArmored_WithoutPassword_ReturnsUnencryptedArmoredKey()
    {
        // Arrange
        var seed = Seed.GenerateRandom();
        var userId = UserId.FromString("Test User");
        using var keySet = KeySet.Create(seed, userId);

        // Act
        var armoredKey = keySet.ExportPrivateKeyArmored();

        // Assert
        Assert.NotNull(armoredKey);
        Assert.Contains("-----BEGIN PGP PRIVATE KEY BLOCK-----", armoredKey);
        Assert.Contains("-----END PGP PRIVATE KEY BLOCK-----", armoredKey);
    }

    [Fact]
    public void ExportPrivateKeyArmored_WithPassword_ThrowsNotImplementedException()
    {
        // Arrange
        var seed = Seed.GenerateRandom();
        var userId = UserId.FromString("Test User");
        using var keySet = KeySet.Create(seed, userId);

        // Act & Assert
        Assert.Throws<NotImplementedException>(() => 
            keySet.ExportPrivateKeyArmored("password123"));
    }

    [Fact]
    public void GetSummary_ReturnsFormattedSummary()
    {
        // Arrange
        var seed = Seed.GenerateRandom();
        var userId = UserId.FromString("Test User <test@example.com>");
        using var keySet = KeySet.Create(seed, userId);

        // Act
        var summary = keySet.GetSummary();

        // Assert
        Assert.Contains("Master Key: Ed25519", summary);
        Assert.Contains("User ID: Test User <test@example.com>", summary);
        Assert.Contains("Subkeys: 3", summary);
        Assert.Contains("Ed25519 (Signing)", summary);
        Assert.Contains("Ed25519 (Authentication)", summary);
        Assert.Contains("Curve25519 (Encryption)", summary);
    }

    [Fact]
    public void AddSubkey_NewSubkey_AddsToCollection()
    {
        // Arrange
        var seed = Seed.GenerateRandom();
        var userId = UserId.FromString("Test User");
        using var keySet = KeySet.FromMasterKey(
            Ed25519MasterKey.FromSeed(seed, DateTime.UtcNow), 
            userId);
        
        var additionalSubkey = Ed25519Subkey.CreateSigningKey(seed, DateTime.UtcNow, 1);

        // Act
        keySet.AddSubkey(additionalSubkey);

        // Assert
        Assert.Contains(additionalSubkey, keySet.Subkeys);
    }

    [Fact]
    public void RemoveSubkey_ExistingSubkey_RemovesFromCollection()
    {
        // Arrange
        var seed = Seed.GenerateRandom();
        var userId = UserId.FromString("Test User");
        using var keySet = KeySet.Create(seed, userId);
        var subkeyToRemove = keySet.GetSigningKey()!;

        // Act
        var removed = keySet.RemoveSubkey(subkeyToRemove);

        // Assert
        Assert.True(removed);
        Assert.DoesNotContain(subkeyToRemove, keySet.Subkeys);
    }


    [Fact]
    public void Fingerprint_ReturnsValidFingerprint()
    {
        // Arrange
        var seed = Seed.GenerateRandom();
        var userId = UserId.FromString("Test User");
        using var keySet = KeySet.Create(seed, userId);

        // Act
        var fingerprint = keySet.Fingerprint;

        // Assert
        Assert.NotNull(fingerprint);
        Assert.Equal(32, fingerprint.Length); // SHA-256 hash
        Assert.Equal(keySet.MasterKey.Fingerprint, fingerprint);
    }

    [Fact]
    public void KeyId_ReturnsValidKeyId()
    {
        // Arrange
        var seed = Seed.GenerateRandom();
        var userId = UserId.FromString("Test User");
        using var keySet = KeySet.Create(seed, userId);

        // Act
        var keyId = keySet.KeyId;

        // Assert
        Assert.NotNull(keyId);
        Assert.Equal(8, keyId.Length);
        Assert.Equal(keySet.MasterKey.KeyId, keyId);
    }

    [Fact]
    public void Dispose_DisposesAllKeys()
    {
        // Arrange
        var seed = Seed.GenerateRandom();
        var userId = UserId.FromString("Test User");
        var keySet = KeySet.Create(seed, userId);

        // Act
        keySet.Dispose();

        // Assert
        Assert.Throws<ObjectDisposedException>(() => keySet.MasterKey.PublicKeyBytes);
        Assert.Throws<ObjectDisposedException>(() => keySet.Fingerprint);
    }

    [Fact]
    public void ToString_ReturnsFormattedString()
    {
        // Arrange
        var seed = Seed.GenerateRandom();
        var userId = UserId.FromString("Test User");
        using var keySet = KeySet.Create(seed, userId);

        // Act
        var result = keySet.ToString();

        // Assert
        Assert.Contains("KeySet", result);
        Assert.Contains("master=", result);
        Assert.Contains("subkeys=3", result);
        Assert.Contains("userId=Test User", result);
    }
}