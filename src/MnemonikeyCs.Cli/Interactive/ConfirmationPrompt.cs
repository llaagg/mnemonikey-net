using System;
using MnemonikeyCs.Cli.Output;
using Spectre.Console;

namespace MnemonikeyCs.Cli.Interactive;

/// <summary>
/// Provides confirmation prompts for various operations.
/// </summary>
public static class ConfirmationPrompt
{
    /// <summary>
    /// Prompts for a simple yes/no confirmation.
    /// </summary>
    /// <param name="message">The confirmation message.</param>
    /// <param name="defaultValue">The default value if user just presses Enter.</param>
    /// <returns>True if confirmed, false otherwise.</returns>
    public static bool Confirm(string message, bool defaultValue = false)
    {
        return ColorConsole.Confirm(message, defaultValue);
    }

    /// <summary>
    /// Prompts for confirmation of a potentially dangerous operation.
    /// </summary>
    /// <param name="operation">Description of the operation.</param>
    /// <param name="warnings">Additional warning messages.</param>
    /// <returns>True if confirmed, false otherwise.</returns>
    public static bool ConfirmDangerousOperation(string operation, params string[] warnings)
    {
        ColorConsole.WriteLine();
        TableFormatter.DisplayWarningBox("Dangerous Operation", warnings);
        ColorConsole.WriteLine();
        
        ColorConsole.WriteError($"You are about to: {operation}");
        ColorConsole.WriteError("This action cannot be undone.");
        ColorConsole.WriteLine();
        
        return ColorConsole.Confirm("Are you absolutely sure you want to continue?", false);
    }

    /// <summary>
    /// Prompts for confirmation with a typed confirmation phrase.
    /// </summary>
    /// <param name="message">The confirmation message.</param>
    /// <param name="confirmationPhrase">The phrase the user must type to confirm.</param>
    /// <param name="caseSensitive">Whether the confirmation phrase is case-sensitive.</param>
    /// <returns>True if confirmed, false otherwise.</returns>
    public static bool ConfirmWithPhrase(string message, string confirmationPhrase = "yes", bool caseSensitive = false)
    {
        ColorConsole.WriteWarning(message);
        ColorConsole.WriteLine();
        
        var prompt = $"Type '{confirmationPhrase}' to confirm";
        var input = ColorConsole.Prompt(prompt, allowEmpty: true);
        
        var comparison = caseSensitive ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase;
        return string.Equals(input, confirmationPhrase, comparison);
    }

    /// <summary>
    /// Prompts for confirmation of key generation with security warnings.
    /// </summary>
    /// <param name="hasExistingKeys">Whether the user might have existing keys.</param>
    /// <returns>True if confirmed, false otherwise.</returns>
    public static bool ConfirmKeyGeneration(bool hasExistingKeys = false)
    {
        var warnings = new List<string>
        {
            "You are about to generate new PGP keys.",
            "📝 You will receive a recovery phrase that must be stored securely.",
            "⚠️  If you lose both the keys and recovery phrase, your data cannot be recovered."
        };
        
        if (hasExistingKeys)
        {
            warnings.Add("🔄 This will create NEW keys separate from any existing keys.");
        }
        
        TableFormatter.DisplayWarningBox("Key Generation", warnings.ToArray());
        ColorConsole.WriteLine();
        
        return ColorConsole.Confirm("Do you want to proceed with key generation?", false);
    }

    /// <summary>
    /// Prompts for confirmation of key recovery with warnings.
    /// </summary>
    /// <returns>True if confirmed, false otherwise.</returns>
    public static bool ConfirmKeyRecovery()
    {
        var warnings = new string[]
        {
            "🔑 You are about to recover PGP keys from a recovery phrase.",
            "📝 Make sure you have the correct recovery phrase available.",
            "⚠️  Incorrect phrases will not generate the correct keys.",
            "🔐 If the phrase is encrypted, you will need the decryption password."
        };
        
        TableFormatter.DisplayWarningBox("Key Recovery", warnings);
        ColorConsole.WriteLine();
        
        return ColorConsole.Confirm("Do you want to proceed with key recovery?", false);
    }

    /// <summary>
    /// Prompts for confirmation of phrase conversion operation.
    /// </summary>
    /// <param name="fromEncrypted">True if converting from encrypted to plaintext, false for the opposite.</param>
    /// <returns>True if confirmed, false otherwise.</returns>
    public static bool ConfirmPhraseConversion(bool fromEncrypted)
    {
        string operation;
        string[] warnings;
        
        if (fromEncrypted)
        {
            operation = "decrypt your recovery phrase";
            warnings = new string[]
            {
                "🔓 You are about to convert an encrypted phrase to plaintext.",
                "📝 The resulting phrase will not be password-protected.",
                "⚠️  Store the plaintext phrase securely - anyone with access can use it.",
                "🔐 You will need the decryption password."
            };
        }
        else
        {
            operation = "encrypt your recovery phrase";
            warnings = new string[]
            {
                "🔐 You are about to convert a plaintext phrase to encrypted format.",
                "📝 You will need to choose an encryption password.",
                "⚠️  If you forget the password, the phrase cannot be decrypted.",
                "💾 The encrypted phrase is longer than the plaintext version."
            };
        }
        
        TableFormatter.DisplayWarningBox("Phrase Conversion", warnings);
        ColorConsole.WriteLine();
        
        return ColorConsole.Confirm($"Do you want to {operation}?", false);
    }

    /// <summary>
    /// Prompts for confirmation of file overwrite.
    /// </summary>
    /// <param name="filePath">The path of the file that would be overwritten.</param>
    /// <returns>True if confirmed, false otherwise.</returns>
    public static bool ConfirmFileOverwrite(string filePath)
    {
        ColorConsole.WriteWarning($"File already exists: {filePath}");
        return ColorConsole.Confirm("Do you want to overwrite it?", false);
    }

    /// <summary>
    /// Prompts for confirmation of outputting sensitive data to console.
    /// </summary>
    /// <param name="dataType">Type of sensitive data (e.g., "private keys", "recovery phrase").</param>
    /// <returns>True if confirmed, false otherwise.</returns>
    public static bool ConfirmSensitiveOutput(string dataType)
    {
        var warnings = new string[]
        {
            $"⚠️  You are about to output {dataType} to the console.",
            "👁️  This information will be visible on your screen.",
            "📺 It may be logged in your terminal history.",
            "🔒 Consider using file output (--output) for better security."
        };
        
        TableFormatter.DisplayWarningBox("Sensitive Data Output", warnings);
        ColorConsole.WriteLine();
        
        return ColorConsole.Confirm($"Do you want to display {dataType} on the console?", false);
    }

    /// <summary>
    /// Prompts the user to acknowledge they have safely stored their recovery phrase.
    /// </summary>
    /// <returns>True if acknowledged, false otherwise.</returns>
    public static bool ConfirmPhraseBackup()
    {
        var requirements = new string[]
        {
            "✅ I have written down my recovery phrase completely and accurately.",
            "✅ I have stored it in a secure location (not on this computer).",
            "✅ I understand that losing this phrase means losing access to my keys.",
            "✅ I have verified the phrase by checking each word carefully."
        };
        
        ColorConsole.WriteRule("🔐 Recovery Phrase Backup Confirmation");
        ColorConsole.WriteLine();
        ColorConsole.WriteHighlight("Please confirm that you have safely stored your recovery phrase:");
        ColorConsole.WriteLine();
        
        foreach (var requirement in requirements)
        {
            ColorConsole.WriteInfo(requirement);
        }
        
        ColorConsole.WriteLine();
        ColorConsole.WriteError("Without this phrase, your keys cannot be recovered if lost!");
        ColorConsole.WriteLine();
        
        return ConfirmWithPhrase(
            "I confirm that I have safely backed up my recovery phrase.", 
            "I have backed up my phrase", 
            caseSensitive: false);
    }

    /// <summary>
    /// Prompts for multiple-step confirmation of a critical operation.
    /// </summary>
    /// <param name="operation">Description of the operation.</param>
    /// <param name="steps">Confirmation steps the user must acknowledge.</param>
    /// <returns>True if all steps are confirmed, false otherwise.</returns>
    public static bool MultiStepConfirmation(string operation, params string[] steps)
    {
        ColorConsole.WriteRule($"⚠️  {operation}");
        ColorConsole.WriteLine();
        
        ColorConsole.WriteError($"You are about to: {operation}");
        ColorConsole.WriteError("Please read and confirm each step:");
        ColorConsole.WriteLine();
        
        for (int i = 0; i < steps.Length; i++)
        {
            ColorConsole.WriteInfo($"Step {i + 1}: {steps[i]}");
            
            if (!ColorConsole.Confirm($"Confirm step {i + 1}?", false))
            {
                ColorConsole.WriteWarning("Operation cancelled.");
                return false;
            }
            
            ColorConsole.WriteLine();
        }
        
        // Final confirmation
        ColorConsole.WriteError("Final confirmation required.");
        return ConfirmWithPhrase(
            $"Type 'CONFIRM' to proceed with: {operation}",
            "CONFIRM",
            caseSensitive: true);
    }

    /// <summary>
    /// Shows a selection prompt for the user to choose from multiple options.
    /// </summary>
    /// <param name="title">Title of the selection.</param>
    /// <param name="options">Available options.</param>
    /// <returns>The selected option, or null if cancelled.</returns>
    public static T? SelectOption<T>(string title, T[] options) where T : class
    {
        if (!options.Any())
        {
            return null;
        }
        
        var choices = options.Cast<string>().ToList();
        choices.Add("[Cancel]");
        
        var prompt = new SelectionPrompt<string>()
            .Title(title)
            .AddChoices(choices);
        
        var selected = prompt.Show(AnsiConsole.Console);
        return selected == "[Cancel]" ? null : (T)(object)selected;
    }

    /// <summary>
    /// Prompts the user to select from a list of choices with descriptions.
    /// </summary>
    /// <param name="title">Title of the selection.</param>
    /// <param name="choices">Choices with their descriptions.</param>
    /// <returns>The selected choice value, or null if cancelled.</returns>
    public static string? SelectFromChoices(string title, Dictionary<string, string> choices)
    {
        if (!choices.Any())
        {
            return null;
        }
        
        var prompt = new SelectionPrompt<string>()
            .Title(title)
            .UseConverter(choice => choices.ContainsKey(choice) ? $"{choice} - {choices[choice]}" : choice)
            .AddChoices(choices.Keys)
            .AddChoices("[Cancel]");
        
        var selected = prompt.Show(AnsiConsole.Console);
        return selected == "[Cancel]" ? null : selected;
    }
}