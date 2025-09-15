using System.Collections.Frozen;

namespace MnemonikeyCs.Mnemonic;

public static class Wordlist4096
{
    public const int WordCount = 4096;
    public const int BitsPerWord = 12;

    private static readonly Lazy<string[]> _wordList = new(LoadWordList);
    private static readonly Lazy<FrozenDictionary<string, ushort>> _wordMap = new(CreateWordMap);

    public static string[] WordList => _wordList.Value;
    public static FrozenDictionary<string, ushort> WordMap => _wordMap.Value;

    private static string[] LoadWordList()
    {
        var assembly = typeof(Wordlist4096).Assembly;
        using var stream = assembly.GetManifestResourceStream("MnemonikeyCs.wordlist4096.txt")
            ?? throw new InvalidOperationException("Wordlist resource not found");
        using var reader = new StreamReader(stream);
        
        var words = new List<string>(WordCount);
        string? line;
        while ((line = reader.ReadLine()) != null)
        {
            if (!string.IsNullOrWhiteSpace(line))
            {
                words.Add(line.Trim().ToLowerInvariant());
            }
        }

        if (words.Count != WordCount)
        {
            throw new InvalidOperationException($"Wordlist must contain exactly {WordCount} words, found {words.Count}");
        }

        return words.ToArray();
    }

    private static FrozenDictionary<string, ushort> CreateWordMap()
    {
        var wordList = WordList;
        var map = new Dictionary<string, ushort>(WordCount);
        
        for (ushort i = 0; i < wordList.Length; i++)
        {
            map[wordList[i]] = i;
        }

        return map.ToFrozenDictionary();
    }

    public static ushort GetWordIndex(string word)
    {
        if (WordMap.TryGetValue(word.ToLowerInvariant(), out var index))
        {
            return index;
        }
        
        throw new ArgumentException($"Word '{word}' not found in wordlist", nameof(word));
    }

    public static string GetWord(ushort index)
    {
        if (index >= WordCount)
        {
            throw new ArgumentOutOfRangeException(nameof(index), $"Index must be less than {WordCount}");
        }
        
        return WordList[index];
    }

    public static bool IsValidWord(string word)
    {
        return WordMap.ContainsKey(word.ToLowerInvariant());
    }
}