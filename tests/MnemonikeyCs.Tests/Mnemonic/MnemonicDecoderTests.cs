using System.Text;
using FluentAssertions;
using MnemonikeyCs.Core;
using MnemonikeyCs.Mnemonic;
using Xunit;
using Xunit.Abstractions;

namespace MnemonikeyCs.Tests.Mnemonic;

[Trait("Category", "Unit")]
public class MnemonicDecoderTests : TestBase
{
    public MnemonicDecoderTests(ITestOutputHelper output) : base(output) { }

    [Fact]
    public void DetectVersion_WithPlaintextPhrase_ShouldReturnPlaintext()
    {
        // Arrange - Create a plaintext phrase
        var seed = Seed.FromHex("0123456789abcdef0123456789abcdef");
        var creationTime = TestCreationTime;
        var words = MnemonicEncoder.EncodeToPlaintext(seed, creationTime);

        // Act
        var version = MnemonicDecoder.DetectVersion(words);

        // Assert
        version.Should().Be(MnemonicVersion.Plaintext);
        version.IsPlaintext.Should().BeTrue();
        version.IsEncrypted.Should().BeFalse();
        
        Log($"Detected version: {version}");
    }

    [Fact]
    public void DetectVersion_WithEncryptedPhrase_ShouldReturnEncrypted()
    {
        // Arrange - Create an encrypted phrase
        var seed = Seed.FromHex("0123456789abcdef0123456789abcdef");
        var creationTime = TestCreationTime;
        var password = Encoding.UTF8.GetBytes("test-password");
        var words = MnemonicEncoder.EncodeToEncrypted(seed, creationTime, password);

        // Act
        var version = MnemonicDecoder.DetectVersion(words);

        // Assert
        version.Should().Be(MnemonicVersion.Encrypted);
        version.IsEncrypted.Should().BeTrue();
        version.IsPlaintext.Should().BeFalse();
        
        Log($"Detected version: {version}");
    }

    [Fact]
    public void DetectVersion_WithEmptyArray_ShouldThrow()
    {
        // Arrange
        var words = Array.Empty<string>();

        // Act & Assert
        var act = () => MnemonicDecoder.DetectVersion(words);
        act.Should().Throw<ArgumentException>()
           .WithMessage("Words array cannot be empty*");
    }

    [Fact]
    public void DecodePlaintext_WithValidPhrase_ShouldRecoverOriginalData()
    {
        // Arrange
        var originalSeed = Seed.FromHex("0123456789abcdef0123456789abcdef");
        var originalCreationTime = TestCreationTime;
        var words = MnemonicEncoder.EncodeToPlaintext(originalSeed, originalCreationTime);

        // Act
        var (recoveredSeed, recoveredCreationTime) = MnemonicDecoder.DecodePlaintext(words);

        // Assert
        recoveredSeed.Should().BeEquivalentTo(originalSeed);
        recoveredCreationTime.Should().Be(originalCreationTime);
        
        Log($"Original seed:     {originalSeed.ToHex()}");
        Log($"Recovered seed:    {recoveredSeed.ToHex()}");
        Log($"Original time:     {originalCreationTime}");
        Log($"Recovered time:    {recoveredCreationTime}");
    }

    [Fact]
    public void DecodeEncrypted_WithValidPhrase_ShouldRecoverOriginalData()
    {
        // Arrange
        var originalSeed = Seed.FromHex("fedcba9876543210fedcba9876543210");
        var originalCreationTime = TestCreationTime;
        var password = Encoding.UTF8.GetBytes("secure-password");
        var words = MnemonicEncoder.EncodeToEncrypted(originalSeed, originalCreationTime, password);

        // Act
        var (recoveredSeed, recoveredCreationTime) = MnemonicDecoder.DecodeEncrypted(words, password);

        // Assert
        recoveredSeed.Should().BeEquivalentTo(originalSeed);
        recoveredCreationTime.Should().Be(originalCreationTime);
        
        Log($"Original seed:     {originalSeed.ToHex()}");
        Log($"Recovered seed:    {recoveredSeed.ToHex()}");
        Log($"Original time:     {originalCreationTime}");
        Log($"Recovered time:    {recoveredCreationTime}");
    }

    [Fact]
    public void DecodePlaintext_WithWrongWordCount_ShouldThrow()
    {
        // Arrange - Too few words
        var words = new[] { "abandon", "abandon", "abandon" };

        // Act & Assert
        var act = () => MnemonicDecoder.DecodePlaintext(words);
        act.Should().Throw<ArgumentException>()
           .WithMessage("Plaintext phrases must contain exactly 14 words*");
    }

    [Fact]
    public void DecodeEncrypted_WithWrongWordCount_ShouldThrow()
    {
        // Arrange - Too few words
        var words = new[] { "abandon", "abandon", "abandon" };
        var password = Encoding.UTF8.GetBytes("password");

        // Act & Assert
        var act = () => MnemonicDecoder.DecodeEncrypted(words, password);
        act.Should().Throw<ArgumentException>()
           .WithMessage("Encrypted phrases must contain exactly 16 words*");
    }

    [Fact]
    public void DecodeEncrypted_WithWrongPassword_ShouldThrow()
    {
        // Arrange
        var seed = Seed.FromHex("0123456789abcdef0123456789abcdef");
        var creationTime = TestCreationTime;
        var correctPassword = Encoding.UTF8.GetBytes("correct-password");
        var wrongPassword = Encoding.UTF8.GetBytes("wrong-password");
        var words = MnemonicEncoder.EncodeToEncrypted(seed, creationTime, correctPassword);

        // Act & Assert
        var act = () => MnemonicDecoder.DecodeEncrypted(words, wrongPassword);
        act.Should().Throw<UnauthorizedAccessException>()
           .WithMessage("Invalid password or corrupted encrypted phrase");
    }

    [Fact]
    public void DecodePlaintext_WithInvalidWord_ShouldThrow()
    {
        // Arrange - Invalid word in phrase
        var words = new[] 
        { 
            "abandon", "abandon", "abandon", "abandon", 
            "abandon", "abandon", "abandon", "abandon",
            "abandon", "abandon", "abandon", "abandon",
            "abandon", "notaword" // Invalid word
        };

        // Act & Assert
        var act = () => MnemonicDecoder.DecodePlaintext(words);
        act.Should().Throw<ArgumentException>()
           .WithMessage("Word 'notaword' not found in wordlist*");
    }

    [Theory]
    [InlineData("00000000000000000000000000000000")]
    [InlineData("ffffffffffffffffffffffffffffffff")]
    [InlineData("0123456789abcdef0123456789abcdef")]
    public void RoundTrip_PlaintextEncoding_ShouldBeIdentical(string hexSeed)
    {
        // Arrange
        var originalSeed = Seed.FromHex(hexSeed);
        var originalCreationTime = TestCreationTime;

        // Act - Encode then decode
        var words = MnemonicEncoder.EncodeToPlaintext(originalSeed, originalCreationTime);
        var (recoveredSeed, recoveredCreationTime) = MnemonicDecoder.DecodePlaintext(words);

        // Assert
        recoveredSeed.Should().BeEquivalentTo(originalSeed);
        recoveredCreationTime.Should().Be(originalCreationTime);
        
        Log($"Round-trip successful for seed: {hexSeed}");
    }

    [Theory]
    [InlineData("password123")]
    [InlineData("")]
    [InlineData("🔐 unicode password")]
    public void RoundTrip_EncryptedEncoding_ShouldBeIdentical(string passwordString)
    {
        // Arrange
        var originalSeed = Seed.FromHex("abcdef0123456789abcdef0123456789");
        var originalCreationTime = TestCreationTime;
        var password = Encoding.UTF8.GetBytes(passwordString);

        // Act - Encode then decode
        var words = MnemonicEncoder.EncodeToEncrypted(originalSeed, originalCreationTime, password);
        var (recoveredSeed, recoveredCreationTime) = MnemonicDecoder.DecodeEncrypted(words, password);

        // Assert
        recoveredSeed.Should().BeEquivalentTo(originalSeed);
        recoveredCreationTime.Should().Be(originalCreationTime);
        
        Log($"Round-trip successful for password: '{passwordString}'");
    }

    [Fact]
    public void DecodePlaintext_WithCorruptedChecksum_ShouldThrow()
    {
        // Arrange - Create valid phrase then corrupt last word
        var seed = Seed.FromHex("0123456789abcdef0123456789abcdef");
        var creationTime = TestCreationTime;
        var words = MnemonicEncoder.EncodeToPlaintext(seed, creationTime);
        
        // Corrupt the last word (which affects the checksum)
        words[13] = "abandon";

        // Act & Assert
        var act = () => MnemonicDecoder.DecodePlaintext(words);
        act.Should().Throw<InvalidDataException>()
           .WithMessage("Checksum mismatch:*");
    }


    [Fact]
    public void RoundTrip_MultipleSeeds_ShouldMaintainUniqueness()
    {
        // Arrange
        var seeds = new[]
        {
            Seed.FromHex("0123456789abcdef0123456789abcdef"),
            Seed.FromHex("fedcba9876543210fedcba9876543210"),
            Seed.FromHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            Seed.FromHex("55555555555555555555555555555555")
        };
        var creationTime = TestCreationTime;

        // Act & Assert
        var recoveredSeeds = new List<Seed>();
        
        foreach (var originalSeed in seeds)
        {
            var words = MnemonicEncoder.EncodeToPlaintext(originalSeed, creationTime);
            var (recoveredSeed, _) = MnemonicDecoder.DecodePlaintext(words);
            
            recoveredSeed.Should().BeEquivalentTo(originalSeed);
            recoveredSeeds.Add(recoveredSeed);
        }

        // All recovered seeds should be unique
        recoveredSeeds.Should().OnlyHaveUniqueItems();
        
        Log("All seeds maintained uniqueness through round-trip encoding");
    }
}