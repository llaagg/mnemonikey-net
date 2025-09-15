using FluentAssertions;
using MnemonikeyCs.Mnemonic;
using Xunit;
using Xunit.Abstractions;

namespace MnemonikeyCs.Tests.Mnemonic;

[Trait("Category", "Unit")]
public class Wordlist4096Tests : TestBase
{
    public Wordlist4096Tests(ITestOutputHelper output) : base(output) { }

    [Fact]
    public void WordCount_ShouldBe4096()
    {
        Wordlist4096.WordCount.Should().Be(4096);
    }

    [Fact]
    public void BitsPerWord_ShouldBe12()
    {
        Wordlist4096.BitsPerWord.Should().Be(12);
    }

    [Fact]
    public void WordList_ShouldContain4096Words()
    {
        var wordList = Wordlist4096.WordList;
        wordList.Should().HaveCount(4096);
    }

    [Fact]
    public void WordList_ShouldContainExpectedWords()
    {
        var wordList = Wordlist4096.WordList;
        
        // Check first few words
        wordList[0].Should().Be("aardvark");
        wordList[1].Should().Be("abacus");
        wordList[2].Should().Be("abalone");
        wordList[3].Should().Be("abandon");
        
        Log($"First 4 words: {string.Join(", ", wordList.Take(4))}");
    }

    [Fact]
    public void WordMap_ShouldMapWordsToCorrectIndices()
    {
        var wordMap = Wordlist4096.WordMap;
        
        wordMap.Should().HaveCount(4096);
        wordMap["aardvark"].Should().Be(0);
        wordMap["abacus"].Should().Be(1);
        wordMap["abalone"].Should().Be(2);
        wordMap["abandon"].Should().Be(3);
        
        Log("Word mapping verification passed");
    }

    [Fact]
    public void GetWordIndex_WithValidWord_ShouldReturnCorrectIndex()
    {
        Wordlist4096.GetWordIndex("aardvark").Should().Be(0);
        Wordlist4096.GetWordIndex("abacus").Should().Be(1);
        Wordlist4096.GetWordIndex("abandon").Should().Be(3);
        
        // Test case insensitivity
        Wordlist4096.GetWordIndex("AARDVARK").Should().Be(0);
        Wordlist4096.GetWordIndex("AbAnDoN").Should().Be(3);
    }

    [Fact]
    public void GetWordIndex_WithInvalidWord_ShouldThrow()
    {
        var act = () => Wordlist4096.GetWordIndex("notaword");
        act.Should().Throw<ArgumentException>()
           .WithMessage("Word 'notaword' not found in wordlist*");
    }

    [Fact]
    public void GetWord_WithValidIndex_ShouldReturnCorrectWord()
    {
        Wordlist4096.GetWord(0).Should().Be("aardvark");
        Wordlist4096.GetWord(1).Should().Be("abacus");
        Wordlist4096.GetWord(3).Should().Be("abandon");
    }

    [Fact]
    public void GetWord_WithInvalidIndex_ShouldThrow()
    {
        var act = () => Wordlist4096.GetWord(4096);
        act.Should().Throw<ArgumentOutOfRangeException>()
           .WithMessage("Index must be less than 4096*");
    }

    [Fact]
    public void IsValidWord_WithValidWord_ShouldReturnTrue()
    {
        Wordlist4096.IsValidWord("aardvark").Should().BeTrue();
        Wordlist4096.IsValidWord("abandon").Should().BeTrue();
        
        // Test case insensitivity
        Wordlist4096.IsValidWord("AARDVARK").Should().BeTrue();
        Wordlist4096.IsValidWord("AbAnDoN").Should().BeTrue();
    }

    [Fact]
    public void IsValidWord_WithInvalidWord_ShouldReturnFalse()
    {
        Wordlist4096.IsValidWord("notaword").Should().BeFalse();
        Wordlist4096.IsValidWord("").Should().BeFalse();
        Wordlist4096.IsValidWord("123").Should().BeFalse();
    }

    [Theory]
    [InlineData(0)]
    [InlineData(100)]
    [InlineData(1000)]
    [InlineData(2000)]
    [InlineData(4095)]
    public void RoundTrip_IndexToWordToIndex_ShouldBeIdentical(ushort originalIndex)
    {
        var word = Wordlist4096.GetWord(originalIndex);
        var recoveredIndex = Wordlist4096.GetWordIndex(word);
        
        recoveredIndex.Should().Be(originalIndex);
        Log($"Index {originalIndex} -> '{word}' -> {recoveredIndex}");
    }

    [Fact]
    public void WordList_ShouldBeAlphabeticallySorted()
    {
        var wordList = Wordlist4096.WordList;
        var sortedList = wordList.OrderBy(w => w).ToArray();
        
        wordList.Should().BeEquivalentTo(sortedList, opt => opt.WithStrictOrdering());
        
        Log("Wordlist is properly sorted alphabetically");
    }

    [Fact]
    public void AllWords_ShouldBeLowercase()
    {
        var wordList = Wordlist4096.WordList;
        
        foreach (var word in wordList)
        {
            word.Should().Be(word.ToLowerInvariant(), 
                $"Word '{word}' should be lowercase");
        }
        
        Log("All words are properly lowercase");
    }

    [Fact]
    public void AllWords_ShouldBeUnique()
    {
        var wordList = Wordlist4096.WordList;
        var uniqueWords = wordList.Distinct().ToArray();
        
        uniqueWords.Should().HaveCount(wordList.Length, "All words should be unique");
        
        Log("All words are unique");
    }
}