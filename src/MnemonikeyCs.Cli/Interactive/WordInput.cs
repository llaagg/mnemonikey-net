using System;
using System.Collections.Generic;
using System.Linq;
using MnemonikeyCs.Cli.Output;
using MnemonikeyCs.Cli.Validation;
using Spectre.Console;
using SpectreValidationResult = Spectre.Console.ValidationResult;

namespace MnemonikeyCs.Cli.Interactive;

/// <summary>
/// Provides interactive mnemonic word entry with validation and autocomplete.
/// </summary>
public static class WordInput
{
    /// <summary>
    /// Prompts the user to enter a complete mnemonic phrase interactively.
    /// </summary>
    /// <param name="expectedWordCount">The expected number of words (15 for plaintext, 18 for encrypted, or null for auto-detect).</param>
    /// <returns>The validated mnemonic phrase as a string array.</returns>
    public static string[] PromptForMnemonicPhrase(int? expectedWordCount = null)
    {
        ColorConsole.WriteRule("Enter Recovery Phrase");
        ColorConsole.WriteInfo("Enter your mnemonic recovery phrase. You can:");
        ColorConsole.WriteInfo("- Type each word and press Enter");
        ColorConsole.WriteInfo("- Paste the entire phrase at once");
        ColorConsole.WriteInfo("- Use Tab for word completion");
        ColorConsole.WriteInfo("- Type 'done' when finished, or 'cancel' to abort");
        ColorConsole.WriteLine();

        var words = new List<string>();
        var wordNumber = 1;

        while (true)
        {
            // Check if we have enough words
            if (expectedWordCount.HasValue && words.Count >= expectedWordCount.Value)
            {
                ColorConsole.WriteSuccess($"Collected all {expectedWordCount.Value} words.");
                break;
            }

            // Prompt for next word
            var prompt = expectedWordCount.HasValue 
                ? $"Word {wordNumber}/{expectedWordCount.Value}"
                : $"Word {wordNumber}";

            var input = PromptForSingleWord(prompt);

            // Handle special commands
            if (string.Equals(input, "done", StringComparison.OrdinalIgnoreCase))
            {
                if (words.Count == 0)
                {
                    ColorConsole.WriteWarning("No words entered yet. Continue adding words or type 'cancel' to abort.");
                    continue;
                }
                break;
            }

            if (string.Equals(input, "cancel", StringComparison.OrdinalIgnoreCase))
            {
                throw new OperationCanceledException("User cancelled word entry.");
            }

            // Check if input contains multiple words (pasted phrase)
            var inputWords = input.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
            
            if (inputWords.Length > 1)
            {
                ColorConsole.WriteInfo($"Processing {inputWords.Length} words from pasted input...");
                
                // Validate each word
                bool allValid = true;
                var validatedWords = new List<string>();
                
                for (int i = 0; i < inputWords.Length; i++)
                {
                    var wordResult = WordValidator.ValidateWord(inputWords[i]);
                    if (wordResult.IsValid)
                    {
                        validatedWords.Add(wordResult.NormalizedWord!);
                    }
                    else
                    {
                        ColorConsole.WriteError($"Invalid word at position {words.Count + i + 1}: '{inputWords[i]}'");
                        if (wordResult.Suggestions?.Any() == true)
                        {
                            ColorConsole.WriteInfo($"Suggestions: {string.Join(", ", wordResult.Suggestions)}");
                        }
                        allValid = false;
                        break;
                    }
                }
                
                if (allValid)
                {
                    words.AddRange(validatedWords);
                    wordNumber += validatedWords.Count;
                    ColorConsole.WriteSuccess($"Added {validatedWords.Count} valid words.");
                    continue;
                }
                else
                {
                    ColorConsole.WriteWarning("Please enter words one at a time to avoid errors.");
                    continue;
                }
            }

            // Validate single word
            var singleWordResult = WordValidator.ValidateWord(input);
            if (singleWordResult.IsValid)
            {
                words.Add(singleWordResult.NormalizedWord!);
                wordNumber++;
                ColorConsole.WriteMuted($"Added: {singleWordResult.NormalizedWord}");
            }
            else
            {
                ColorConsole.WriteError(singleWordResult.ErrorMessage!);
                if (singleWordResult.Suggestions?.Any() == true)
                {
                    ColorConsole.WriteInfo($"Did you mean: {string.Join(", ", singleWordResult.Suggestions)}?");
                    
                    // Ask if user wants to use first suggestion
                    if (ColorConsole.Confirm($"Use '{singleWordResult.Suggestions[0]}' instead?", false))
                    {
                        words.Add(singleWordResult.Suggestions[0]);
                        wordNumber++;
                        ColorConsole.WriteSuccess($"Added: {singleWordResult.Suggestions[0]}");
                    }
                }
            }
        }

        // Final validation of the complete phrase
        ColorConsole.WriteLine();
        ColorConsole.WriteInfo("Validating complete phrase...");
        
        var phraseResult = WordValidator.ValidatePhrase(string.Join(" ", words));
        if (!phraseResult.IsValid)
        {
            ColorConsole.WriteError("Phrase validation failed:");
            ColorConsole.WriteError(phraseResult.ErrorMessage!);
            
            if (ColorConsole.Confirm("Would you like to try entering the phrase again?", true))
            {
                return PromptForMnemonicPhrase(expectedWordCount);
            }
            else
            {
                throw new InvalidOperationException("Invalid mnemonic phrase entered.");
            }
        }

        ColorConsole.WriteSuccess($"Successfully validated {words.Count}-word mnemonic phrase.");
        return phraseResult.ValidatedWords!;
    }

    /// <summary>
    /// Prompts for a single word with autocomplete support.
    /// </summary>
    /// <param name="prompt">The prompt to display.</param>
    /// <returns>The entered word.</returns>
    public static string PromptForSingleWord(string prompt)
    {
        var textPrompt = new TextPrompt<string>($"[cyan]{prompt}:[/]")
            .ValidationErrorMessage("[red]Please enter a word[/]")
            .Validate(input => 
            {
                if (string.IsNullOrWhiteSpace(input))
                {
                    return SpectreValidationResult.Error("Word cannot be empty");
                }
                
                // Allow special commands
                var trimmed = input.Trim();
                if (string.Equals(trimmed, "done", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(trimmed, "cancel", StringComparison.OrdinalIgnoreCase))
                {
                    return SpectreValidationResult.Success();
                }
                
                // For pasted input (multiple words), allow it through
                if (trimmed.Contains(' '))
                {
                    return SpectreValidationResult.Success();
                }
                
                // Validate single words
                var wordResult = WordValidator.ValidateWord(trimmed);
                if (wordResult.IsValid)
                {
                    return SpectreValidationResult.Success();
                }
                else
                {
                    var message = wordResult.ErrorMessage!;
                    if (wordResult.Suggestions?.Any() == true)
                    {
                        message += $" (suggestions: {string.Join(", ", wordResult.Suggestions)})";
                    }
                    return SpectreValidationResult.Error(message);
                }
            });

        return textPrompt.Show(AnsiConsole.Console);
    }

    /// <summary>
    /// Displays word suggestions based on partial input.
    /// </summary>
    /// <param name="partialWord">The partial word to find suggestions for.</param>
    /// <param name="maxSuggestions">Maximum number of suggestions to display.</param>
    public static void ShowWordSuggestions(string partialWord, int maxSuggestions = 10)
    {
        if (string.IsNullOrWhiteSpace(partialWord) || partialWord.Length < 2)
        {
            return;
        }

        var suggestions = WordValidator.GetWordsStartingWith(partialWord, maxSuggestions);
        if (suggestions.Any())
        {
            ColorConsole.WriteInfo($"Words starting with '{partialWord}':");
            var columns = Math.Min(5, suggestions.Length);
            var rows = (suggestions.Length + columns - 1) / columns;
            
            for (int row = 0; row < rows; row++)
            {
                var rowWords = new List<string>();
                for (int col = 0; col < columns; col++)
                {
                    var index = row + col * rows;
                    if (index < suggestions.Length)
                    {
                        rowWords.Add($"[green]{suggestions[index]}[/]");
                    }
                }
                
                if (rowWords.Any())
                {
                    AnsiConsole.MarkupLine(string.Join("  ", rowWords));
                }
            }
        }
        else
        {
            // Try substring search if no prefix matches found
            var containingSuggestions = WordValidator.GetWordsContaining(partialWord, maxSuggestions);
            if (containingSuggestions.Any())
            {
                ColorConsole.WriteInfo($"Words containing '{partialWord}':");
                ColorConsole.WriteInfo(string.Join(", ", containingSuggestions.Select(w => $"[green]{w}[/]")));
            }
        }
    }

    /// <summary>
    /// Displays the current phrase being entered for user review.
    /// </summary>
    /// <param name="words">The words entered so far.</param>
    public static void ShowCurrentPhrase(IList<string> words)
    {
        if (!words.Any())
        {
            ColorConsole.WriteMuted("No words entered yet.");
            return;
        }

        ColorConsole.WriteLine();
        ColorConsole.WriteRule("Current Phrase");
        
        // Display words in a grid format
        var columns = Math.Min(3, words.Count);
        var rows = (words.Count + columns - 1) / columns;
        
        var table = new Table()
            .BorderColor(Color.Grey)
            .HideHeaders();
        
        for (int col = 0; col < columns; col++)
        {
            table.AddColumn(new TableColumn("").LeftAligned());
        }
        
        for (int row = 0; row < rows; row++)
        {
            var rowData = new string[columns];
            
            for (int col = 0; col < columns; col++)
            {
                var index = row + col * rows;
                if (index < words.Count)
                {
                    rowData[col] = $"[grey]{index + 1,2}.[/] [green]{words[index]}[/]";
                }
                else
                {
                    rowData[col] = "";
                }
            }
            
            table.AddRow(rowData);
        }
        
        AnsiConsole.Write(table);
        ColorConsole.WriteLine();
    }

    /// <summary>
    /// Prompts the user to select from a list of word suggestions.
    /// </summary>
    /// <param name="suggestions">The list of word suggestions.</param>
    /// <param name="prompt">The prompt to display.</param>
    /// <returns>The selected word, or null if cancelled.</returns>
    public static string? SelectFromSuggestions(string[] suggestions, string prompt = "Select a word:")
    {
        if (!suggestions.Any())
        {
            return null;
        }

        var selectionPrompt = new SelectionPrompt<string>()
            .Title(prompt)
            .AddChoices(suggestions)
            .AddChoices("[Cancel]");

        var selected = selectionPrompt.Show(AnsiConsole.Console);
        return selected == "[Cancel]" ? null : selected;
    }

    /// <summary>
    /// Prompts the user to confirm the entered mnemonic phrase.
    /// </summary>
    /// <param name="words">The words to confirm.</param>
    /// <returns>True if confirmed, false otherwise.</returns>
    public static bool ConfirmPhrase(string[] words)
    {
        ColorConsole.WriteLine();
        ColorConsole.WriteRule("Confirm Recovery Phrase");
        TableFormatter.DisplayMnemonicWords(words, "Your Recovery Phrase", showNumbers: true);
        
        ColorConsole.WriteWarning("Please verify that you have recorded this phrase safely.");
        ColorConsole.WriteWarning("This phrase is required to recover your PGP keys.");
        
        return ColorConsole.Confirm("Is this recovery phrase correct?", false);
    }
}