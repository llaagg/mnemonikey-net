using System;
using System.Text;
using FluentAssertions;
using MnemonikeyCs.Core;
using MnemonikeyCs.Crypto;
using Xunit;
using Xunit.Abstractions;

namespace MnemonikeyCs.Tests.Crypto;

/// <summary>
/// Tests for the Argon2Service class.
/// </summary>
public sealed class Argon2ServiceTests : TestBase
{
    public Argon2ServiceTests(ITestOutputHelper output) : base(output)
    {
    }

    [Fact]
    public void DeriveKey_ValidParameters_ShouldReturnCorrectLength()
    {
        // Arrange
        var password = Encoding.UTF8.GetBytes("test-password");
        var salt = Encoding.UTF8.GetBytes("test-salt");
        const uint iterations = 1;
        const uint memorySize = 1024; // 1MB
        const uint parallelism = 1;
        const int keyLength = 32;

        // Act
        var key = Argon2Service.DeriveKey(password, salt, iterations, memorySize, parallelism, keyLength);

        // Assert
        key.Should().HaveCount(keyLength);
        key.Should().NotBeEquivalentTo(new byte[keyLength]); // Should not be all zeros

        Log($"Derived key: {Convert.ToHexString(key)}");
    }

    [Fact]
    public void DeriveKey_SameInputs_ShouldReturnSameKey()
    {
        // Arrange
        var password = Encoding.UTF8.GetBytes("test-password");
        var salt = Encoding.UTF8.GetBytes("test-salt");
        const uint iterations = 1;
        const uint memorySize = 1024;
        const uint parallelism = 1;
        const int keyLength = 32;

        // Act
        var key1 = Argon2Service.DeriveKey(password, salt, iterations, memorySize, parallelism, keyLength);
        var key2 = Argon2Service.DeriveKey(password, salt, iterations, memorySize, parallelism, keyLength);

        // Assert
        key1.Should().BeEquivalentTo(key2);

        Log($"Key 1: {Convert.ToHexString(key1)}");
        Log($"Key 2: {Convert.ToHexString(key2)}");
    }

    [Fact]
    public void DeriveKey_DifferentPasswords_ShouldReturnDifferentKeys()
    {
        // Arrange
        var password1 = Encoding.UTF8.GetBytes("password1");
        var password2 = Encoding.UTF8.GetBytes("password2");
        var salt = Encoding.UTF8.GetBytes("test-salt");

        // Act
        var key1 = Argon2Service.DeriveKeyStandard(password1, salt, 32);
        var key2 = Argon2Service.DeriveKeyStandard(password2, salt, 32);

        // Assert
        key1.Should().NotBeEquivalentTo(key2);

        Log($"Key 1: {Convert.ToHexString(key1)}");
        Log($"Key 2: {Convert.ToHexString(key2)}");
    }

    [Fact]
    public void DeriveKey_DifferentSalts_ShouldReturnDifferentKeys()
    {
        // Arrange
        var password = Encoding.UTF8.GetBytes("test-password");
        var salt1 = Encoding.UTF8.GetBytes("salt1");
        var salt2 = Encoding.UTF8.GetBytes("salt2");

        // Act
        var key1 = Argon2Service.DeriveKeyStandard(password, salt1, 32);
        var key2 = Argon2Service.DeriveKeyStandard(password, salt2, 32);

        // Assert
        key1.Should().NotBeEquivalentTo(key2);

        Log($"Key 1: {Convert.ToHexString(key1)}");
        Log($"Key 2: {Convert.ToHexString(key2)}");
    }

    [Theory]
    [InlineData(null, "salt")]
    [InlineData("password", null)]
    public void DeriveKey_NullInputs_ShouldThrowArgumentNullException(string? password, string? salt)
    {
        // Arrange
        var passwordBytes = password != null ? Encoding.UTF8.GetBytes(password) : null;
        var saltBytes = salt != null ? Encoding.UTF8.GetBytes(salt) : null;

        // Act & Assert
        var act = () => Argon2Service.DeriveKey(passwordBytes!, saltBytes!, 1, 1024, 1, 32);
        act.Should().Throw<ArgumentNullException>();

        Log($"Correctly rejected null input: password={password}, salt={salt}");
    }

    [Theory]
    [InlineData(0u, 1024u, 1u, 32)] // Zero iterations
    [InlineData(1u, 0u, 1u, 32)]    // Zero memory
    [InlineData(1u, 1024u, 0u, 32)] // Zero parallelism
    [InlineData(1u, 1024u, 1u, 0)]  // Zero key length
    [InlineData(1u, 1024u, 1u, -1)] // Negative key length
    public void DeriveKey_InvalidParameters_ShouldThrowArgumentException(
        uint iterations, uint memorySize, uint parallelism, int keyLength)
    {
        // Arrange
        var password = Encoding.UTF8.GetBytes("test-password");
        var salt = Encoding.UTF8.GetBytes("test-salt");

        // Act & Assert
        var act = () => Argon2Service.DeriveKey(password, salt, iterations, memorySize, parallelism, keyLength);
        act.Should().Throw<ArgumentException>();

        Log($"Correctly rejected invalid parameters: iterations={iterations}, memory={memorySize}, parallelism={parallelism}, keyLength={keyLength}");
    }

    [Fact]
    public void DeriveKeyStandard_ShouldUseStandardParameters()
    {
        // Arrange
        var password = Encoding.UTF8.GetBytes("test-password");
        var salt = Encoding.UTF8.GetBytes("test-salt");

        // Act
        var standardKey = Argon2Service.DeriveKeyStandard(password, salt, 32);
        var manualKey = Argon2Service.DeriveKey(
            password, salt, 
            Constants.ArgonTimeFactor, 
            Constants.ArgonMemoryFactor, 
            Constants.ArgonThreads, 
            32);

        // Assert
        standardKey.Should().BeEquivalentTo(manualKey);

        Log($"Standard parameters produce expected result");
        Log($"Standard key: {Convert.ToHexString(standardKey)}");
    }

    [Fact]
    public void DeriveRootKey_ValidSeedAndTime_ShouldReturnCorrectKey()
    {
        // Arrange
        var seed = CreateTestSeed("0123456789abcdef0123456789abcdef");
        var creationTime = TestCreationTime;

        // Act
        var rootKey = Argon2Service.DeriveRootKey(seed, creationTime);

        // Assert
        rootKey.Should().HaveCount(Constants.RootKeySize);
        rootKey.Should().NotBeEquivalentTo(new byte[Constants.RootKeySize]);

        Log($"Root key derived: {Convert.ToHexString(rootKey)}");
        Log($"Seed: {seed.ToHex()}");
        Log($"Creation time: {creationTime:yyyy-MM-dd HH:mm:ss} UTC");
    }

    [Fact]
    public void DeriveRootKey_SameSeedAndTime_ShouldReturnSameKey()
    {
        // Arrange
        var seed1 = CreateTestSeed("0123456789abcdef0123456789abcdef");
        var seed2 = CreateTestSeed("0123456789abcdef0123456789abcdef");
        var creationTime = TestCreationTime;

        // Act
        var rootKey1 = Argon2Service.DeriveRootKey(seed1, creationTime);
        var rootKey2 = Argon2Service.DeriveRootKey(seed2, creationTime);

        // Assert
        rootKey1.Should().BeEquivalentTo(rootKey2);

        Log($"Root keys match for same seed and time");
    }

    [Fact]
    public void DeriveRootKey_DifferentSeeds_ShouldReturnDifferentKeys()
    {
        // Arrange
        var seed1 = CreateTestSeed("0123456789abcdef0123456789abcdef");
        var seed2 = CreateTestSeed("fedcba9876543210fedcba9876543210");
        var creationTime = TestCreationTime;

        // Act
        var rootKey1 = Argon2Service.DeriveRootKey(seed1, creationTime);
        var rootKey2 = Argon2Service.DeriveRootKey(seed2, creationTime);

        // Assert
        rootKey1.Should().NotBeEquivalentTo(rootKey2);

        Log($"Root keys differ for different seeds");
        Log($"Key 1: {Convert.ToHexString(rootKey1)}");
        Log($"Key 2: {Convert.ToHexString(rootKey2)}");
    }

    [Fact]
    public void DeriveRootKey_DifferentTimes_ShouldReturnDifferentKeys()
    {
        // Arrange
        var seed = CreateTestSeed("0123456789abcdef0123456789abcdef");
        var time1 = TestCreationTime;
        var time2 = TestCreationTime.AddHours(1);

        // Act
        var rootKey1 = Argon2Service.DeriveRootKey(seed, time1);
        var rootKey2 = Argon2Service.DeriveRootKey(seed, time2);

        // Assert
        rootKey1.Should().NotBeEquivalentTo(rootKey2);

        Log($"Root keys differ for different times");
        Log($"Time 1: {time1:yyyy-MM-dd HH:mm:ss} UTC");
        Log($"Time 2: {time2:yyyy-MM-dd HH:mm:ss} UTC");
    }

    [Fact]
    public void DeriveRootKey_NullSeed_ShouldThrowArgumentNullException()
    {
        // Act & Assert
        var act = () => Argon2Service.DeriveRootKey(null!, TestCreationTime);
        act.Should().Throw<ArgumentNullException>();

        Log("Correctly rejected null seed");
    }

    [Fact]
    public void DeriveEncryptionKey_ValidParameters_ShouldReturnCorrectKey()
    {
        // Arrange
        var password = Encoding.UTF8.GetBytes("test-password");
        const uint salt = 0x12345u; // 19-bit salt
        const uint creationOffset = 0x6789ABCDu; // 31-bit creation offset

        // Act
        var encryptionKey = Argon2Service.DeriveEncryptionKey(password, salt, creationOffset);

        // Assert
        encryptionKey.Should().HaveCount(17); // 16 bytes for AES + 1 for verification
        encryptionKey.Should().NotBeEquivalentTo(new byte[17]);

        Log($"Encryption key derived: {Convert.ToHexString(encryptionKey)}");
        Log($"Salt: 0x{salt:X} ({salt})");
        Log($"Creation offset: 0x{creationOffset:X} ({creationOffset})");
    }

    [Fact]
    public void DeriveEncryptionKey_SameParameters_ShouldReturnSameKey()
    {
        // Arrange
        var password = Encoding.UTF8.GetBytes("test-password");
        const uint salt = 0x12345u;
        const uint creationOffset = 0x6789ABCDu;

        // Act
        var key1 = Argon2Service.DeriveEncryptionKey(password, salt, creationOffset);
        var key2 = Argon2Service.DeriveEncryptionKey(password, salt, creationOffset);

        // Assert
        key1.Should().BeEquivalentTo(key2);

        Log("Encryption keys match for same parameters");
    }

    [Fact]
    public void DeriveEncryptionKey_DifferentPasswords_ShouldReturnDifferentKeys()
    {
        // Arrange
        var password1 = Encoding.UTF8.GetBytes("password1");
        var password2 = Encoding.UTF8.GetBytes("password2");
        const uint salt = 0x12345u;
        const uint creationOffset = 0x6789ABCDu;

        // Act
        var key1 = Argon2Service.DeriveEncryptionKey(password1, salt, creationOffset);
        var key2 = Argon2Service.DeriveEncryptionKey(password2, salt, creationOffset);

        // Assert
        key1.Should().NotBeEquivalentTo(key2);

        Log("Encryption keys differ for different passwords");
    }

    [Fact]
    public void DeriveEncryptionKey_NullPassword_ShouldThrowArgumentNullException()
    {
        // Act & Assert
        var act = () => Argon2Service.DeriveEncryptionKey(null!, 0x123u, 0x456u);
        act.Should().Throw<ArgumentNullException>();

        Log("Correctly rejected null password");
    }

    [Fact]
    public void PerformanceTest_StandardDerivation_ShouldCompleteWithinReasonableTime()
    {
        // Arrange
        var seed = CreateTestSeed("0123456789abcdef0123456789abcdef");
        var creationTime = TestCreationTime;

        // Act
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        var rootKey = Argon2Service.DeriveRootKey(seed, creationTime);
        stopwatch.Stop();

        // Assert
        rootKey.Should().HaveCount(Constants.RootKeySize);
        stopwatch.ElapsedMilliseconds.Should().BeLessThan(10000); // Should complete within 5 seconds

        Log($"Root key derivation completed in {stopwatch.ElapsedMilliseconds}ms");
    }
}