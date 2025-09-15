using System.Text;
using FluentAssertions;
using MnemonikeyCs.Core;
using MnemonikeyCs.Mnemonic;
using Xunit;
using Xunit.Abstractions;

namespace MnemonikeyCs.Tests.Mnemonic;

[Trait("Category", "Unit")]
public class MnemonicEncoderTests : TestBase
{
    public MnemonicEncoderTests(ITestOutputHelper output) : base(output) { }

    [Fact]
    public void EncodeToPlaintext_WithValidInputs_ShouldReturn14Words()
    {
        // Arrange
        var seed = Seed.FromHex("0123456789abcdef0123456789abcdef");
        var creationTime = TestCreationTime;

        // Act
        var words = MnemonicEncoder.EncodeToPlaintext(seed, creationTime);

        // Assert
        words.Should().HaveCount(14);
        words.Should().OnlyContain(word => Wordlist4096.IsValidWord(word));
        
        Log($"Encoded plaintext phrase: {string.Join(" ", words)}");
    }

    [Fact]
    public void EncodeToEncrypted_WithValidInputs_ShouldReturn16Words()
    {
        // Arrange
        var seed = Seed.FromHex("0123456789abcdef0123456789abcdef");
        var creationTime = TestCreationTime;
        var password = Encoding.UTF8.GetBytes("test-password");

        // Act
        var words = MnemonicEncoder.EncodeToEncrypted(seed, creationTime, password);

        // Assert
        words.Should().HaveCount(16);
        words.Should().OnlyContain(word => Wordlist4096.IsValidWord(word));
        
        Log($"Encoded encrypted phrase: {string.Join(" ", words)}");
    }


    [Fact]
    public void EncodeToPlaintext_WithDifferentCreationTimes_ShouldProduceDifferentPhrases()
    {
        // Arrange
        var seed = Seed.FromHex("0123456789abcdef0123456789abcdef");
        var creationTime1 = TestCreationTime;
        var creationTime2 = TestCreationTime.AddHours(1);

        // Act
        var words1 = MnemonicEncoder.EncodeToPlaintext(seed, creationTime1);
        var words2 = MnemonicEncoder.EncodeToPlaintext(seed, creationTime2);

        // Assert
        words1.Should().NotBeEquivalentTo(words2);
        
        Log($"Time1 phrase: {string.Join(" ", words1)}");
        Log($"Time2 phrase: {string.Join(" ", words2)}");
    }

    [Fact]
    public void EncodeToEncrypted_WithDifferentPasswords_ShouldProduceDifferentPhrases()
    {
        // Arrange
        var seed = Seed.FromHex("0123456789abcdef0123456789abcdef");
        var creationTime = TestCreationTime;
        var password1 = Encoding.UTF8.GetBytes("password1");
        var password2 = Encoding.UTF8.GetBytes("password2");

        // Act
        var words1 = MnemonicEncoder.EncodeToEncrypted(seed, creationTime, password1);
        var words2 = MnemonicEncoder.EncodeToEncrypted(seed, creationTime, password2);

        // Assert
        words1.Should().NotBeEquivalentTo(words2);
        
        Log($"Password1 phrase: {string.Join(" ", words1)}");
        Log($"Password2 phrase: {string.Join(" ", words2)}");
    }

    [Fact]
    public void EncodeToPlaintext_WithSameInputs_ShouldBeConsistent()
    {
        // Arrange
        var seed = Seed.FromHex("0123456789abcdef0123456789abcdef");
        var creationTime = TestCreationTime;

        // Act
        var words1 = MnemonicEncoder.EncodeToPlaintext(seed, creationTime);
        var words2 = MnemonicEncoder.EncodeToPlaintext(seed, creationTime);

        // Assert
        words1.Should().BeEquivalentTo(words2, opt => opt.WithStrictOrdering());
        
        Log($"Consistent phrase: {string.Join(" ", words1)}");
    }

    [Fact]
    public void EncodeToEncrypted_WithSameInputsDifferentSalts_ShouldProduceDifferentPhrases()
    {
        // Arrange
        var seed = Seed.FromHex("0123456789abcdef0123456789abcdef");
        var creationTime = TestCreationTime;
        var password = Encoding.UTF8.GetBytes("test-password");

        // Act - Multiple calls should produce different results due to random salt
        var words1 = MnemonicEncoder.EncodeToEncrypted(seed, creationTime, password);
        var words2 = MnemonicEncoder.EncodeToEncrypted(seed, creationTime, password);

        // Assert - Should be different due to random salt
        words1.Should().NotBeEquivalentTo(words2);
        
        Log($"First encrypted phrase:  {string.Join(" ", words1)}");
        Log($"Second encrypted phrase: {string.Join(" ", words2)}");
    }

    [Theory]
    [InlineData("00000000000000000000000000000000")]
    [InlineData("ffffffffffffffffffffffffffffffff")]
    [InlineData("0123456789abcdef0123456789abcdef")]
    public void EncodeToPlaintext_WithEdgeCaseSeeds_ShouldWork(string hexSeed)
    {
        // Arrange
        var seed = Seed.FromHex(hexSeed);
        var creationTime = TestCreationTime;

        // Act
        var words = MnemonicEncoder.EncodeToPlaintext(seed, creationTime);

        // Assert
        words.Should().HaveCount(14);
        words.Should().OnlyContain(word => Wordlist4096.IsValidWord(word));
        
        Log($"Seed {hexSeed} -> {string.Join(" ", words)}");
    }

    [Fact]
    public void EncodeToPlaintext_WithMinimumCreationTime_ShouldWork()
    {
        // Arrange
        var seed = Seed.FromHex("0123456789abcdef0123456789abcdef");
        var creationTime = Constants.EpochStart; // Minimum valid time

        // Act
        var words = MnemonicEncoder.EncodeToPlaintext(seed, creationTime);

        // Assert
        words.Should().HaveCount(14);
        words.Should().OnlyContain(word => Wordlist4096.IsValidWord(word));
        
        Log($"Minimum time phrase: {string.Join(" ", words)}");
    }

    [Fact]
    public void EncodeToPlaintext_WithCreationTimeBeforeEpoch_ShouldThrow()
    {
        // Arrange
        var seed = Seed.FromHex("0123456789abcdef0123456789abcdef");
        var creationTime = Constants.EpochStart.AddSeconds(-1);

        // Act & Assert
        var act = () => MnemonicEncoder.EncodeToPlaintext(seed, creationTime);
        act.Should().Throw<ArgumentException>()
           .WithMessage("Creation time cannot be before 2023-01-01*");
    }

    [Fact]
    public void EncodeToEncrypted_WithEmptyPassword_ShouldWork()
    {
        // Arrange
        var seed = Seed.FromHex("0123456789abcdef0123456789abcdef");
        var creationTime = TestCreationTime;
        var password = Array.Empty<byte>();

        // Act
        var words = MnemonicEncoder.EncodeToEncrypted(seed, creationTime, password);

        // Assert
        words.Should().HaveCount(16);
        words.Should().OnlyContain(word => Wordlist4096.IsValidWord(word));
        
        Log($"Empty password phrase: {string.Join(" ", words)}");
    }
}