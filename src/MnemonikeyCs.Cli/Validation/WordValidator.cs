using System;
using System.Collections.Generic;
using System.Linq;
using MnemonikeyCs.Mnemonic;

namespace MnemonikeyCs.Cli.Validation;

/// <summary>
/// Provides mnemonic word validation and suggestion functionality.
/// </summary>
public static class WordValidator
{
    /// <summary>
    /// Validates a single mnemonic word.
    /// </summary>
    /// <param name="word">The word to validate.</param>
    /// <returns>A validation result.</returns>
    public static WordValidationResult ValidateWord(string? word)
    {
        if (string.IsNullOrWhiteSpace(word))
        {
            return WordValidationResult.Error("Word cannot be empty.");
        }

        var normalizedWord = NormalizeWord(word);

        // Check if word exists in wordlist
        if (Wordlist4096.WordMap.ContainsKey(normalizedWord))
        {
            return WordValidationResult.Success(normalizedWord);
        }

        // Word not found, try to suggest alternatives
        var suggestions = GetWordSuggestions(normalizedWord, maxSuggestions: 5);
        
        if (suggestions.Any())
        {
            return WordValidationResult.Error(
                $"Word '{normalizedWord}' is not in the wordlist.", 
                suggestions);
        }
        else
        {
            return WordValidationResult.Error($"Word '{normalizedWord}' is not in the wordlist.");
        }
    }

    /// <summary>
    /// Validates a complete mnemonic phrase.
    /// </summary>
    /// <param name="phrase">The mnemonic phrase to validate.</param>
    /// <returns>A phrase validation result.</returns>
    public static PhraseValidationResult ValidatePhrase(string? phrase)
    {
        if (string.IsNullOrWhiteSpace(phrase))
        {
            return PhraseValidationResult.Error("Phrase cannot be empty.");
        }

        var words = phrase.Split(new[] { ' ', '\t', '\n', '\r' }, 
            StringSplitOptions.RemoveEmptyEntries);

        if (words.Length == 0)
        {
            return PhraseValidationResult.Error("Phrase must contain at least one word.");
        }

        // Validate expected word count
        var expectedWordCounts = new[] { 15, 18 }; // Plaintext: 15, Encrypted: 18
        if (!expectedWordCounts.Contains(words.Length))
        {
            return PhraseValidationResult.Error(
                $"Phrase must contain exactly {string.Join(" or ", expectedWordCounts)} words, " +
                $"but found {words.Length} words.");
        }

        // Validate each word
        var invalidWords = new List<(int Index, string Word, string[] Suggestions)>();
        var validatedWords = new List<string>();

        for (int i = 0; i < words.Length; i++)
        {
            var wordResult = ValidateWord(words[i]);
            if (wordResult.IsValid)
            {
                validatedWords.Add(wordResult.NormalizedWord!);
            }
            else
            {
                invalidWords.Add((i, words[i], wordResult.Suggestions ?? Array.Empty<string>()));
            }
        }

        if (invalidWords.Any())
        {
            var errorMessages = invalidWords.Select(invalid =>
                $"Word {invalid.Index + 1}: '{invalid.Word}' is not valid" +
                (invalid.Suggestions.Any() 
                    ? $" (suggestions: {string.Join(", ", invalid.Suggestions)})"
                    : ""));
            
            return PhraseValidationResult.Error(
                "Phrase contains invalid words:\n" + string.Join("\n", errorMessages));
        }

        // Try to decode the phrase to verify checksum
        try
        {
            var isValid = Mnemonikey.IsValidMnemonic(string.Join(" ", validatedWords));
            if (!isValid)
            {
                return PhraseValidationResult.Error(
                    "Phrase checksum validation failed. The phrase may be corrupted or incomplete.");
            }

            return PhraseValidationResult.Success(validatedWords.ToArray());
        }
        catch (Exception ex)
        {
            return PhraseValidationResult.Error($"Phrase validation failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Checks if a word is valid (exists in the wordlist).
    /// </summary>
    /// <param name="word">The word to check.</param>
    /// <returns>True if valid, false otherwise.</returns>
    public static bool IsValidWord(string? word)
    {
        return ValidateWord(word).IsValid;
    }

    /// <summary>
    /// Normalizes a word (trims and converts to lowercase).
    /// </summary>
    /// <param name="word">The word to normalize.</param>
    /// <returns>The normalized word.</returns>
    public static string NormalizeWord(string word)
    {
        if (string.IsNullOrWhiteSpace(word))
        {
            return string.Empty;
        }

        return word.Trim().ToLowerInvariant();
    }

    /// <summary>
    /// Gets word suggestions for a potentially misspelled word.
    /// </summary>
    /// <param name="word">The word to find suggestions for.</param>
    /// <param name="maxSuggestions">Maximum number of suggestions to return.</param>
    /// <returns>An array of suggested words.</returns>
    public static string[] GetWordSuggestions(string word, int maxSuggestions = 5)
    {
        if (string.IsNullOrWhiteSpace(word))
        {
            return Array.Empty<string>();
        }

        var normalizedWord = NormalizeWord(word);
        var suggestions = new List<(string Word, int Distance)>();

        // Find words with similar length and spelling
        foreach (var validWord in Wordlist4096.WordList)
        {
            var distance = CalculateLevenshteinDistance(normalizedWord, validWord);
            
            // Only consider words with reasonable distance
            if (distance <= Math.Max(1, normalizedWord.Length / 3))
            {
                suggestions.Add((validWord, distance));
            }
        }

        // Sort by distance and return top suggestions
        return suggestions
            .OrderBy(s => s.Distance)
            .ThenBy(s => Math.Abs(s.Word.Length - normalizedWord.Length))
            .Take(maxSuggestions)
            .Select(s => s.Word)
            .ToArray();
    }

    /// <summary>
    /// Gets words that start with a given prefix (for autocomplete).
    /// </summary>
    /// <param name="prefix">The prefix to search for.</param>
    /// <param name="maxResults">Maximum number of results to return.</param>
    /// <returns>An array of matching words.</returns>
    public static string[] GetWordsStartingWith(string prefix, int maxResults = 10)
    {
        if (string.IsNullOrWhiteSpace(prefix))
        {
            return Array.Empty<string>();
        }

        var normalizedPrefix = NormalizeWord(prefix);
        
        return Wordlist4096.WordList
            .Where(word => word.StartsWith(normalizedPrefix, StringComparison.OrdinalIgnoreCase))
            .Take(maxResults)
            .ToArray();
    }

    /// <summary>
    /// Gets words that contain a given substring.
    /// </summary>
    /// <param name="substring">The substring to search for.</param>
    /// <param name="maxResults">Maximum number of results to return.</param>
    /// <returns>An array of matching words.</returns>
    public static string[] GetWordsContaining(string substring, int maxResults = 10)
    {
        if (string.IsNullOrWhiteSpace(substring))
        {
            return Array.Empty<string>();
        }

        var normalizedSubstring = NormalizeWord(substring);
        
        return Wordlist4096.WordList
            .Where(word => word.Contains(normalizedSubstring, StringComparison.OrdinalIgnoreCase))
            .Take(maxResults)
            .ToArray();
    }

    /// <summary>
    /// Gets a random selection of valid words (for testing/examples).
    /// </summary>
    /// <param name="count">Number of words to return.</param>
    /// <returns>An array of random valid words.</returns>
    public static string[] GetRandomWords(int count)
    {
        if (count <= 0)
        {
            return Array.Empty<string>();
        }

        var random = new Random();
        return Wordlist4096.WordList
            .OrderBy(_ => random.Next())
            .Take(Math.Min(count, Wordlist4096.WordList.Length))
            .ToArray();
    }

    /// <summary>
    /// Calculates the Levenshtein distance between two strings.
    /// </summary>
    /// <param name="source">The source string.</param>
    /// <param name="target">The target string.</param>
    /// <returns>The edit distance between the strings.</returns>
    private static int CalculateLevenshteinDistance(string source, string target)
    {
        if (string.IsNullOrEmpty(source))
        {
            return string.IsNullOrEmpty(target) ? 0 : target.Length;
        }

        if (string.IsNullOrEmpty(target))
        {
            return source.Length;
        }

        var matrix = new int[source.Length + 1, target.Length + 1];

        // Initialize first row and column
        for (int i = 0; i <= source.Length; i++)
        {
            matrix[i, 0] = i;
        }
        
        for (int j = 0; j <= target.Length; j++)
        {
            matrix[0, j] = j;
        }

        // Fill the matrix
        for (int i = 1; i <= source.Length; i++)
        {
            for (int j = 1; j <= target.Length; j++)
            {
                var cost = source[i - 1] == target[j - 1] ? 0 : 1;

                matrix[i, j] = Math.Min(
                    Math.Min(
                        matrix[i - 1, j] + 1,     // Deletion
                        matrix[i, j - 1] + 1      // Insertion
                    ),
                    matrix[i - 1, j - 1] + cost   // Substitution
                );
            }
        }

        return matrix[source.Length, target.Length];
    }
}

/// <summary>
/// Represents the result of a word validation operation.
/// </summary>
public class WordValidationResult
{
    /// <summary>
    /// Gets whether the validation was successful.
    /// </summary>
    public bool IsValid { get; private set; }

    /// <summary>
    /// Gets the normalized word if validation was successful.
    /// </summary>
    public string? NormalizedWord { get; private set; }

    /// <summary>
    /// Gets the error message if validation failed.
    /// </summary>
    public string? ErrorMessage { get; private set; }

    /// <summary>
    /// Gets suggested corrections if validation failed.
    /// </summary>
    public string[]? Suggestions { get; private set; }

    /// <summary>
    /// Creates a successful validation result.
    /// </summary>
    /// <param name="normalizedWord">The normalized word.</param>
    /// <returns>A successful validation result.</returns>
    public static WordValidationResult Success(string normalizedWord) => new() 
    { 
        IsValid = true, 
        NormalizedWord = normalizedWord 
    };

    /// <summary>
    /// Creates a failed validation result with an error message.
    /// </summary>
    /// <param name="errorMessage">The error message.</param>
    /// <param name="suggestions">Optional suggestions for correction.</param>
    /// <returns>A failed validation result.</returns>
    public static WordValidationResult Error(string errorMessage, string[]? suggestions = null) => new() 
    { 
        IsValid = false, 
        ErrorMessage = errorMessage,
        Suggestions = suggestions
    };
}

/// <summary>
/// Represents the result of a phrase validation operation.
/// </summary>
public class PhraseValidationResult
{
    /// <summary>
    /// Gets whether the validation was successful.
    /// </summary>
    public bool IsValid { get; private set; }

    /// <summary>
    /// Gets the validated words if validation was successful.
    /// </summary>
    public string[]? ValidatedWords { get; private set; }

    /// <summary>
    /// Gets the error message if validation failed.
    /// </summary>
    public string? ErrorMessage { get; private set; }

    /// <summary>
    /// Creates a successful validation result.
    /// </summary>
    /// <param name="validatedWords">The validated words.</param>
    /// <returns>A successful validation result.</returns>
    public static PhraseValidationResult Success(string[] validatedWords) => new() 
    { 
        IsValid = true, 
        ValidatedWords = validatedWords 
    };

    /// <summary>
    /// Creates a failed validation result with an error message.
    /// </summary>
    /// <param name="errorMessage">The error message.</param>
    /// <returns>A failed validation result.</returns>
    public static PhraseValidationResult Error(string errorMessage) => new() 
    { 
        IsValid = false, 
        ErrorMessage = errorMessage 
    };
}