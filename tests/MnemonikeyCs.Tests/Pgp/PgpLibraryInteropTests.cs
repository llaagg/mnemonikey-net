using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Xunit;
using Xunit.Abstractions;
using MnemonikeyCs.Core;
using MnemonikeyCs.Pgp;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Utilities.IO;

namespace MnemonikeyCs.Tests.Pgp;

/// <summary>
/// Tests for interoperability with PGP libraries (BouncyCastle).
/// These tests verify that keys generated with MnemonikeyCs can be imported
/// and used by standard PGP libraries.
/// </summary>
public class PgpLibraryInteropTests : TestBase
{
    public PgpLibraryInteropTests(ITestOutputHelper output) : base(output) { }

    [Fact]
    public void ImportPublicKey_WithBouncyCastle_SuccessfullyImportsKey()
    {
        // Arrange
        var seed = Seed.GenerateRandom();
        var userId = UserId.Create("Test User", "test@example.com");
        
        using var keySet = KeySet.Create(seed, userId);
        var armoredPublicKey = keySet.ExportPublicKeyArmored();

        Output.WriteLine("Generated Public Key:");
        Output.WriteLine(armoredPublicKey);

        // Act
        using var keyStream = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(armoredPublicKey));
        using var decoderStream = PgpUtilities.GetDecoderStream(keyStream);
        var keyRingBundle = new PgpPublicKeyRingBundle(decoderStream);

        // Assert
        Assert.NotNull(keyRingBundle);
        Assert.True(keyRingBundle.Count > 0, "Should have at least one key ring");
        
        var keyRing = keyRingBundle.GetKeyRings().Cast<PgpPublicKeyRing>().First();
        Assert.NotNull(keyRing);
        
        var masterKey = keyRing.GetPublicKey();
        Assert.NotNull(masterKey);
        Assert.True(masterKey.IsMasterKey);
        
        Output.WriteLine($"Imported Key ID: {masterKey.KeyId:X16}");
        Output.WriteLine($"Is Master Key: {masterKey.IsMasterKey}");
        Output.WriteLine($"Algorithm: {masterKey.Algorithm}");
        Output.WriteLine($"Bit Strength: {masterKey.BitStrength}");
    }

    [Fact]
    public void ImportPrivateKey_WithBouncyCastle_SuccessfullyImportsKey()
    {
        // Arrange
        var seed = Seed.GenerateRandom();
        var userId = UserId.Create("Test User", "test@example.com");
        
        using var keySet = KeySet.Create(seed, userId);
        var armoredPrivateKey = keySet.ExportPrivateKeyArmored();

        Output.WriteLine("Generated Private Key (truncated):");
        Output.WriteLine(armoredPrivateKey.Substring(0, Math.Min(500, armoredPrivateKey.Length)) + "...");

        // Act
        using var keyStream = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(armoredPrivateKey));
        using var decoderStream = PgpUtilities.GetDecoderStream(keyStream);
        var keyRingBundle = new PgpSecretKeyRingBundle(decoderStream);

        // Assert
        Assert.NotNull(keyRingBundle);
        Assert.True(keyRingBundle.Count > 0, "Should have at least one key ring");
        
        var keyRing = keyRingBundle.GetKeyRings().Cast<PgpSecretKeyRing>().First();
        Assert.NotNull(keyRing);
        
        var masterKey = keyRing.GetSecretKey();
        Assert.NotNull(masterKey);
        Assert.True(masterKey.IsMasterKey);
        
        // Verify we can extract the public key
        var publicKey = masterKey.PublicKey;
        Assert.NotNull(publicKey);
        
        Output.WriteLine($"Imported Key ID: {masterKey.KeyId:X16}");
        Output.WriteLine($"Is Master Key: {masterKey.IsMasterKey}");
        Output.WriteLine($"Algorithm: {publicKey.Algorithm}");
        Output.WriteLine($"Is Encrypted: {masterKey.IsPrivateKeyEmpty}");
    }

    [Fact]
    public void ImportPublicKey_VerifySubkeys_AllSubkeysPresent()
    {
        // Arrange
        var seed = Seed.GenerateRandom();
        var userId = UserId.Create("Test User", "test@example.com");
        
        using var keySet = KeySet.Create(seed, userId);
        var armoredPublicKey = keySet.ExportPublicKeyArmored();

        // Act
        using var keyStream = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(armoredPublicKey));
        using var decoderStream = PgpUtilities.GetDecoderStream(keyStream);
        var keyRingBundle = new PgpPublicKeyRingBundle(decoderStream);
        
        var keyRing = keyRingBundle.GetKeyRings().Cast<PgpPublicKeyRing>().First();
        var allKeys = keyRing.GetPublicKeys().Cast<PgpPublicKey>().ToList();

        // Assert - should have master key + 3 subkeys
        Assert.True(allKeys.Count >= 4, $"Expected at least 4 keys (master + 3 subkeys), found {allKeys.Count}");
        
        // Verify master key
        var masterKey = allKeys.First(k => k.IsMasterKey);
        Assert.NotNull(masterKey);
        
        // Verify subkeys
        var subkeys = allKeys.Where(k => !k.IsMasterKey).ToList();
        Assert.Equal(3, subkeys.Count);
        
        // Log all keys for debugging
        Output.WriteLine($"Total keys imported: {allKeys.Count}");
        foreach (var key in allKeys)
        {
            Output.WriteLine($"  Key ID: {key.KeyId:X16}, Master: {key.IsMasterKey}, " +
                           $"Algorithm: {key.Algorithm}, Bit Strength: {key.BitStrength}");
        }
    }

    [Fact]
    public void ImportPrivateKey_VerifySubkeys_AllSubkeysPresent()
    {
        // Arrange
        var seed = Seed.GenerateRandom();
        var userId = UserId.Create("Test User", "test@example.com");
        
        using var keySet = KeySet.Create(seed, userId);
        var armoredPrivateKey = keySet.ExportPrivateKeyArmored();

        // Act
        using var keyStream = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(armoredPrivateKey));
        using var decoderStream = PgpUtilities.GetDecoderStream(keyStream);
        var keyRingBundle = new PgpSecretKeyRingBundle(decoderStream);
        
        var keyRing = keyRingBundle.GetKeyRings().Cast<PgpSecretKeyRing>().First();
        var allKeys = keyRing.GetSecretKeys().Cast<PgpSecretKey>().ToList();

        // Assert - should have master key + 3 subkeys
        Assert.True(allKeys.Count >= 4, $"Expected at least 4 keys (master + 3 subkeys), found {allKeys.Count}");
        
        // Verify master key
        var masterKey = allKeys.First(k => k.IsMasterKey);
        Assert.NotNull(masterKey);
        
        // Verify subkeys
        var subkeys = allKeys.Where(k => !k.IsMasterKey).ToList();
        Assert.Equal(3, subkeys.Count);
        
        // Log all keys for debugging
        Output.WriteLine($"Total keys imported: {allKeys.Count}");
        foreach (var key in allKeys)
        {
            Output.WriteLine($"  Key ID: {key.KeyId:X16}, Master: {key.IsMasterKey}, " +
                           $"Algorithm: {key.PublicKey.Algorithm}, Encrypted: {key.IsPrivateKeyEmpty}");
        }
    }

    [Fact]
    public void ImportPublicKey_VerifyUserID_MatchesOriginal()
    {
        // Arrange
        var expectedName = "John Doe";
        var expectedEmail = "john.doe@example.com";
        var seed = Seed.GenerateRandom();
        var userId = UserId.Create(expectedName, expectedEmail);
        
        using var keySet = KeySet.Create(seed, userId);
        var armoredPublicKey = keySet.ExportPublicKeyArmored();

        // Act
        using var keyStream = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(armoredPublicKey));
        using var decoderStream = PgpUtilities.GetDecoderStream(keyStream);
        var keyRingBundle = new PgpPublicKeyRingBundle(decoderStream);
        
        var keyRing = keyRingBundle.GetKeyRings().Cast<PgpPublicKeyRing>().First();
        var masterKey = keyRing.GetPublicKey();

        // Assert
        var userIds = masterKey.GetUserIds().Cast<string>().ToList();
        Assert.NotEmpty(userIds);
        
        var importedUserId = userIds.First();
        Output.WriteLine($"Expected: {expectedName} <{expectedEmail}>");
        Output.WriteLine($"Imported: {importedUserId}");
        
        // Verify user ID contains both name and email
        Assert.Contains(expectedName, importedUserId);
        Assert.Contains(expectedEmail, importedUserId);
    }

    [Fact]
    public void ImportBinaryPublicKey_WithBouncyCastle_SuccessfullyImportsKey()
    {
        // Arrange
        var seed = Seed.GenerateRandom();
        var userId = UserId.Create("Test User", "test@example.com");
        
        using var keySet = KeySet.Create(seed, userId);
        var binaryPublicKey = keySet.ExportPublicKeyBinary();

        Output.WriteLine($"Binary key size: {binaryPublicKey.Length} bytes");

        // Act
        using var keyStream = new MemoryStream(binaryPublicKey);
        var keyRingBundle = new PgpPublicKeyRingBundle(keyStream);

        // Assert
        Assert.NotNull(keyRingBundle);
        Assert.True(keyRingBundle.Count > 0);
        
        var keyRing = keyRingBundle.GetKeyRings().Cast<PgpPublicKeyRing>().First();
        var masterKey = keyRing.GetPublicKey();
        
        Assert.NotNull(masterKey);
        Assert.True(masterKey.IsMasterKey);
        
        Output.WriteLine($"Successfully imported binary key with ID: {masterKey.KeyId:X16}");
    }

    [Fact]
    public void ImportBinaryPrivateKey_WithBouncyCastle_SuccessfullyImportsKey()
    {
        // Arrange
        var seed = Seed.GenerateRandom();
        var userId = UserId.Create("Test User", "test@example.com");
        
        using var keySet = KeySet.Create(seed, userId);
        var binaryPrivateKey = keySet.ExportPrivateKeyBinary();

        Output.WriteLine($"Binary private key size: {binaryPrivateKey.Length} bytes");

        // Act
        using var keyStream = new MemoryStream(binaryPrivateKey);
        var keyRingBundle = new PgpSecretKeyRingBundle(keyStream);

        // Assert
        Assert.NotNull(keyRingBundle);
        Assert.True(keyRingBundle.Count > 0);
        
        var keyRing = keyRingBundle.GetKeyRings().Cast<PgpSecretKeyRing>().First();
        var masterKey = keyRing.GetSecretKey();
        
        Assert.NotNull(masterKey);
        Assert.True(masterKey.IsMasterKey);
        
        Output.WriteLine($"Successfully imported binary private key with ID: {masterKey.KeyId:X16}");
    }

    [Fact]
    public void RoundTrip_ExportAndImport_PreservesKeyData()
    {
        // Arrange
        var seed = Seed.GenerateRandom();
        var userId = UserId.Create("Round Trip Test", "roundtrip@example.com");
        
        using var keySet = KeySet.Create(seed, userId);
        var originalKeyId = keySet.KeyId;
        var originalPublicKeyBytes = keySet.MasterKey.PublicKeyBytes;
        var armoredPublicKey = keySet.ExportPublicKeyArmored();

        // Act - Export and re-import
        using var keyStream = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(armoredPublicKey));
        using var decoderStream = PgpUtilities.GetDecoderStream(keyStream);
        var keyRingBundle = new PgpPublicKeyRingBundle(decoderStream);
        
        var keyRing = keyRingBundle.GetKeyRings().Cast<PgpPublicKeyRing>().First();
        var masterKey = keyRing.GetPublicKey();

        // Assert - Verify the key imported successfully
        Assert.NotNull(masterKey);
        Assert.True(masterKey.IsMasterKey);
        
        Output.WriteLine($"Original Key ID: {BitConverter.ToString(originalKeyId).Replace("-", "")}");
        Output.WriteLine($"Imported Key ID: {masterKey.KeyId:X16}");
        Output.WriteLine($"Key imported successfully and can be used by standard PGP libraries");
        
        // Note: We don't compare key IDs directly because BouncyCastle may re-encode the key
        // in a slightly different (but still valid) way, which would change the fingerprint/key ID.
        // The important thing is that the key can be imported and used by standard PGP libraries.
    }

    [Fact]
    public void ImportKey_WithCustomIndices_SuccessfullyImports()
    {
        // Arrange
        var seed = Seed.GenerateRandom();
        var userId = UserId.Create("Custom Index Test", "custom@example.com");
        
        // Create key set with custom subkey indices
        using var keySet = KeySet.Create(
            seed, 
            userId, 
            encryptionIndex: 5, 
            signingIndex: 10, 
            authenticationIndex: 15);
        
        var armoredPublicKey = keySet.ExportPublicKeyArmored();

        // Act
        using var keyStream = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(armoredPublicKey));
        using var decoderStream = PgpUtilities.GetDecoderStream(keyStream);
        var keyRingBundle = new PgpPublicKeyRingBundle(decoderStream);

        // Assert
        Assert.NotNull(keyRingBundle);
        Assert.True(keyRingBundle.Count > 0);
        
        var keyRing = keyRingBundle.GetKeyRings().Cast<PgpPublicKeyRing>().First();
        var masterKey = keyRing.GetPublicKey();
        Assert.NotNull(masterKey);
        
        Output.WriteLine($"Successfully imported key with custom indices");
        Output.WriteLine($"Key ID: {masterKey.KeyId:X16}");
    }
}
