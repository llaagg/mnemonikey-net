using System;
using Xunit;
using Xunit.Abstractions;
using MnemonikeyCs.Core;
using MnemonikeyCs.Pgp;

namespace MnemonikeyCs.Tests;

public class MnemonikeyTests : TestBase
{
    public MnemonikeyTests(ITestOutputHelper output) : base(output) { }
    [Fact]
    public void EncodeMnemonic_ValidSeedAndTime_ReturnsMnemonic()
    {
        // Arrange
        var seed = Seed.GenerateRandom();
        var creationTime = DateTime.UtcNow;

        // Act
        var mnemonic = Mnemonikey.EncodeMnemonic(seed, creationTime);

        // Assert
        Assert.NotNull(mnemonic);
        Assert.True(mnemonic.Split(' ').Length >= 12); // At least 12 words for plaintext phrase
    }

    [Fact]
    public void DecodeMnemonic_ValidMnemonic_ReturnsOriginalSeedAndTime()
    {
        // Arrange
        var originalSeed = Seed.GenerateRandom();
        var originalTime = DateTime.UtcNow.Date; // Truncate to avoid precision issues
        var mnemonic = Mnemonikey.EncodeMnemonic(originalSeed, originalTime);

        // Act
        var (decodedSeed, decodedTime) = Mnemonikey.DecodeMnemonic(mnemonic);

        // Assert
        Assert.Equal(originalSeed.ToBytes(), decodedSeed.ToBytes());
        Assert.Equal(originalTime, decodedTime);
    }

    [Fact]
    public void GenerateRandomSeed_ReturnsValidSeed()
    {
        // Act
        var seed = Mnemonikey.GenerateRandomSeed();

        // Assert
        Assert.NotNull(seed);
        Assert.Equal(16, seed.ToBytes().Length);
    }

    [Fact]
    public void CreateSeedFromHex_ValidHex_ReturnsCorrectSeed()
    {
        // Arrange
        var hexString = "0123456789abcdef0123456789abcdef";

        // Act
        var seed = Mnemonikey.CreateSeedFromHex(hexString);

        // Assert
        Assert.Equal(hexString, seed.ToHex());
    }

    [Fact]
    public void GeneratePgpKeySet_FromMnemonic_CreatesValidKeySet()
    {
        // Arrange
        var seed = Seed.GenerateRandom();
        var creationTime = DateTime.UtcNow;
        var mnemonic = Mnemonikey.EncodeMnemonic(seed, creationTime);
        var userId = "Test User <test@example.com>";

        // Act
        using var keySet = Mnemonikey.GeneratePgpKeySet(mnemonic, userId);

        // Assert
        Assert.NotNull(keySet);
        Assert.NotNull(keySet.MasterKey);
        Assert.Equal(userId, keySet.PrimaryUserId.Value);
        Assert.Equal(3, keySet.Subkeys.Count);
    }

    [Fact]
    public void GeneratePgpKeySet_FromSeed_CreatesValidKeySet()
    {
        // Arrange
        var seed = Seed.GenerateRandom();
        var creationTime = DateTime.UtcNow;
        var userId = "Test User";

        // Act
        using var keySet = Mnemonikey.GeneratePgpKeySet(seed, creationTime, userId);

        // Assert
        Assert.NotNull(keySet);
        Assert.NotNull(keySet.MasterKey);
        Assert.Equal(userId, keySet.PrimaryUserId.Value);
        Assert.Equal(3, keySet.Subkeys.Count);
    }

    [Fact]
    public void GeneratePgpKeySet_WithCustomOptions_UsesOptions()
    {
        // Arrange
        var seed = Seed.GenerateRandom();
        var creationTime = DateTime.UtcNow;
        var userId = "Test User";
        var options = Mnemonikey.PgpOptions.WithIndices(1, 2, 3);

        // Act
        using var keySet = Mnemonikey.GeneratePgpKeySet(seed, creationTime, userId, options);

        // Assert
        Assert.Equal(1, keySet.GetEncryptionKey()!.Index);
        Assert.Equal(2, keySet.GetSigningKey()!.Index);
        Assert.Equal(3, keySet.GetAuthenticationKey()!.Index);
    }

    [Fact]
    public void ExportPgpArmored_DefaultOptions_ReturnsPrivateKeyArmored()
    {
        // Arrange
        var seed = Seed.GenerateRandom();
        var creationTime = DateTime.UtcNow;
        var userId = "Test User";
        using var keySet = Mnemonikey.GeneratePgpKeySet(seed, creationTime, userId);

        // Act
        var armored = Mnemonikey.ExportPgpArmored(keySet);

        // Assert
        Assert.Contains("-----BEGIN PGP PRIVATE KEY BLOCK-----", armored);
        Assert.Contains("-----END PGP PRIVATE KEY BLOCK-----", armored);
    }

    [Fact]
    public void ExportPgpArmored_PublicOnlyOption_ReturnsPublicKeyArmored()
    {
        // Arrange
        var seed = Seed.GenerateRandom();
        var creationTime = DateTime.UtcNow;
        var userId = "Test User";
        using var keySet = Mnemonikey.GeneratePgpKeySet(seed, creationTime, userId);
        var options = Mnemonikey.PgpOptions.PublicOnly();

        // Act
        var armored = Mnemonikey.ExportPgpArmored(keySet, options);

        // Assert
        Assert.Contains("-----BEGIN PGP PUBLIC KEY BLOCK-----", armored);
        Assert.Contains("-----END PGP PUBLIC KEY BLOCK-----", armored);
    }

    [Fact]
    public void ExportPgpBinary_ReturnsValidBinaryData()
    {
        // Arrange
        var seed = Seed.GenerateRandom();
        var creationTime = DateTime.UtcNow;
        var userId = "Test User";
        using var keySet = Mnemonikey.GeneratePgpKeySet(seed, creationTime, userId);

        // Act
        var binaryData = Mnemonikey.ExportPgpBinary(keySet);

        // Assert
        Assert.NotNull(binaryData);
        Assert.True(binaryData.Length > 0);
    }

    [Fact]
    public void CreateNewPgpKey_ReturnsValidMnemonicAndKeySet()
    {
        // Arrange
        var userId = "New User <new@example.com>";

        // Act
        var (mnemonic, keySet) = Mnemonikey.CreateNewPgpKey(userId);

        // Assert
        Assert.NotNull(mnemonic);
        Assert.NotNull(keySet);
        Assert.True(mnemonic.Split(' ').Length >= 12);
        Assert.Equal(userId, keySet.PrimaryUserId.Value);

        keySet.Dispose();
    }

    [Fact]
    public void CreateNewPgpKey_WithOptions_UsesOptions()
    {
        // Arrange
        var userId = "New User";
        var options = Mnemonikey.PgpOptions.WithIndices(5, 6, 7);

        // Act
        var (mnemonic, keySet) = Mnemonikey.CreateNewPgpKey(userId, options);

        // Assert
        Assert.Equal(5, keySet.GetEncryptionKey()!.Index);
        Assert.Equal(6, keySet.GetSigningKey()!.Index);
        Assert.Equal(7, keySet.GetAuthenticationKey()!.Index);

        keySet.Dispose();
    }

    [Fact]
    public void IsValidMnemonic_ValidMnemonic_ReturnsTrue()
    {
        // Arrange
        var seed = Seed.GenerateRandom();
        var creationTime = DateTime.UtcNow;
        var mnemonic = Mnemonikey.EncodeMnemonic(seed, creationTime);

        // Act
        var isValid = Mnemonikey.IsValidMnemonic(mnemonic);

        // Assert
        Assert.True(isValid);
    }

    [Fact]
    public void IsValidMnemonic_InvalidMnemonic_ReturnsFalse()
    {
        // Arrange
        var invalidMnemonic = "this is not a valid mnemonic phrase at all";

        // Act
        var isValid = Mnemonikey.IsValidMnemonic(invalidMnemonic);

        // Assert
        Assert.False(isValid);
    }

    [Fact]
    public void IsValidMnemonic_NullOrEmpty_ReturnsFalse()
    {
        // Act & Assert
        Assert.False(Mnemonikey.IsValidMnemonic(null));
        Assert.False(Mnemonikey.IsValidMnemonic(""));
        Assert.False(Mnemonikey.IsValidMnemonic("   "));
    }

    [Fact]
    public void GetMnemonicInfo_ValidMnemonic_ReturnsInfo()
    {
        // Arrange
        var seed = Seed.GenerateRandom();
        var creationTime = new DateTime(2023, 6, 15, 12, 30, 0, DateTimeKind.Utc);
        var mnemonic = Mnemonikey.EncodeMnemonic(seed, creationTime);

        // Act
        var info = Mnemonikey.GetMnemonicInfo(mnemonic);

        // Assert
        Assert.NotNull(info);
        Assert.True(info.WordCount >= 12);
        Assert.Equal(creationTime, info.CreationTime);
        Assert.Equal(seed.ToHex(), info.SeedHex);
        Assert.Equal(Era.Current, info.Era);
    }

    [Fact]
    public void PgpOptions_Default_HasCorrectDefaults()
    {
        // Act
        var options = Mnemonikey.PgpOptions.Default();

        // Assert
        Assert.Equal(0, options.EncryptionIndex);
        Assert.Equal(0, options.SigningIndex);
        Assert.Equal(0, options.AuthenticationIndex);
        Assert.Null(options.Password);
        Assert.True(options.IncludePrivateKeys);
    }

    [Fact]
    public void PgpOptions_WithIndices_SetsIndices()
    {
        // Act
        var options = Mnemonikey.PgpOptions.WithIndices(1, 2, 3);

        // Assert
        Assert.Equal(1, options.EncryptionIndex);
        Assert.Equal(2, options.SigningIndex);
        Assert.Equal(3, options.AuthenticationIndex);
    }

    [Fact]
    public void PgpOptions_WithPassword_SetsPassword()
    {
        // Act
        var options = Mnemonikey.PgpOptions.WithPassword("test123");

        // Assert
        Assert.Equal("test123", options.Password);
    }

    [Fact]
    public void PgpOptions_PublicOnly_SetsIncludePrivateKeysToFalse()
    {
        // Act
        var options = Mnemonikey.PgpOptions.PublicOnly();

        // Assert
        Assert.False(options.IncludePrivateKeys);
    }

    [Fact]
    public void RoundTrip_EncodeDecode_PreservesData()
    {
        // Arrange
        var originalSeed = Seed.GenerateRandom();
        var originalTime = new DateTime(2023, 1, 1, 12, 0, 0, DateTimeKind.Utc);

        // Act
        var encoded = Mnemonikey.EncodeMnemonic(originalSeed, originalTime);
        var (decodedSeed, decodedTime) = Mnemonikey.DecodeMnemonic(encoded);

        // Assert
        Assert.Equal(originalSeed.ToHex(), decodedSeed.ToHex());
        Assert.Equal(originalTime, decodedTime);
    }
}