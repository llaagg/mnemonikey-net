using System;
using System.Security;
using System.Text;
using MnemonikeyCs.Cli.Output;
using Spectre.Console;

namespace MnemonikeyCs.Cli.Interactive;

/// <summary>
/// Provides secure password input functionality.
/// </summary>
public static class PasswordPrompt
{
    /// <summary>
    /// Prompts for a password with confirmation.
    /// </summary>
    /// <param name="prompt">The prompt message.</param>
    /// <param name="requireConfirmation">Whether to require password confirmation.</param>
    /// <param name="minimumLength">Minimum password length (0 for no minimum).</param>
    /// <param name="allowEmpty">Whether to allow empty passwords.</param>
    /// <returns>The entered password as a UTF-8 byte array.</returns>
    public static byte[] PromptForPassword(
        string prompt = "Enter password", 
        bool requireConfirmation = true, 
        int minimumLength = 8,
        bool allowEmpty = false)
    {
        while (true)
        {
            // Get password
            var password = PromptForSinglePassword(prompt, allowEmpty, minimumLength);
            
            if (!requireConfirmation)
            {
                return password;
            }

            // Get confirmation
            var confirmation = PromptForSinglePassword("Confirm password", allowEmpty, minimumLength);
            
            // Check if passwords match
            if (ArePasswordsEqual(password, confirmation))
            {
                // Clear confirmation from memory
                Array.Clear(confirmation, 0, confirmation.Length);
                return password;
            }
            else
            {
                ColorConsole.WriteError("Passwords do not match. Please try again.");
                ColorConsole.WriteLine();
                
                // Clear both passwords from memory
                Array.Clear(password, 0, password.Length);
                Array.Clear(confirmation, 0, confirmation.Length);
            }
        }
    }

    /// <summary>
    /// Prompts for an existing password (no confirmation required).
    /// </summary>
    /// <param name="prompt">The prompt message.</param>
    /// <param name="allowEmpty">Whether to allow empty passwords.</param>
    /// <returns>The entered password as a UTF-8 byte array.</returns>
    public static byte[] PromptForExistingPassword(string prompt = "Enter password", bool allowEmpty = false)
    {
        return PromptForSinglePassword(prompt, allowEmpty, minimumLength: 0);
    }

    /// <summary>
    /// Prompts for a password for PGP key encryption.
    /// </summary>
    /// <param name="forEncryption">True if this is for encrypting keys, false for decrypting.</param>
    /// <returns>The entered password as a UTF-8 byte array.</returns>
    public static byte[] PromptForPgpPassword(bool forEncryption = true)
    {
        if (forEncryption)
        {
            ColorConsole.WriteRule("PGP Key Password");
            ColorConsole.WriteInfo("Enter a password to protect your PGP private keys.");
            ColorConsole.WriteInfo("This password will be required to use your private keys.");
            ColorConsole.WriteWarning("Choose a strong password and store it securely!");
            ColorConsole.WriteLine();
            
            return PromptForPassword(
                "PGP key password",
                requireConfirmation: true,
                minimumLength: 8,
                allowEmpty: false);
        }
        else
        {
            ColorConsole.WriteRule("PGP Key Password");
            ColorConsole.WriteInfo("Enter the password for your PGP private keys.");
            ColorConsole.WriteLine();
            
            return PromptForExistingPassword("PGP key password", allowEmpty: false);
        }
    }

    /// <summary>
    /// Prompts for a password for mnemonic phrase encryption.
    /// </summary>
    /// <param name="forEncryption">True if this is for encrypting a phrase, false for decrypting.</param>
    /// <returns>The entered password as a UTF-8 byte array.</returns>
    public static byte[] PromptForPhrasePassword(bool forEncryption = true)
    {
        if (forEncryption)
        {
            ColorConsole.WriteRule("Recovery Phrase Password");
            ColorConsole.WriteInfo("Enter a password to encrypt your recovery phrase.");
            ColorConsole.WriteInfo("This creates an encrypted phrase that requires the password to use.");
            ColorConsole.WriteWarning("If you forget this password, you cannot recover your keys!");
            ColorConsole.WriteLine();
            
            return PromptForPassword(
                "Recovery phrase password",
                requireConfirmation: true,
                minimumLength: 8,
                allowEmpty: false);
        }
        else
        {
            ColorConsole.WriteRule("Recovery Phrase Password");
            ColorConsole.WriteInfo("Enter the password to decrypt your recovery phrase.");
            ColorConsole.WriteLine();
            
            return PromptForExistingPassword("Recovery phrase password", allowEmpty: false);
        }
    }

    /// <summary>
    /// Prompts to confirm a potentially destructive action.
    /// </summary>
    /// <param name="action">Description of the action.</param>
    /// <param name="confirmationText">Text user must type to confirm.</param>
    /// <returns>True if confirmed, false otherwise.</returns>
    public static bool ConfirmDestructiveAction(string action, string confirmationText = "yes")
    {
        ColorConsole.WriteWarning($"You are about to {action}.");
        ColorConsole.WriteWarning("This action cannot be undone.");
        ColorConsole.WriteLine();
        
        var input = ColorConsole.Prompt($"Type '{confirmationText}' to confirm", allowEmpty: true);
        return string.Equals(input, confirmationText, StringComparison.Ordinal);
    }

    /// <summary>
    /// Shows password strength information.
    /// </summary>
    /// <param name="password">The password to analyze.</param>
    public static void ShowPasswordStrength(ReadOnlySpan<byte> password)
    {
        var passwordString = Encoding.UTF8.GetString(password);
        var strength = AnalyzePasswordStrength(passwordString);
        
        var color = strength.Level switch
        {
            PasswordStrengthLevel.VeryWeak => Color.Red,
            PasswordStrengthLevel.Weak => Color.Orange1,
            PasswordStrengthLevel.Fair => Color.Yellow,
            PasswordStrengthLevel.Good => Color.Green,
            PasswordStrengthLevel.Excellent => Color.DarkGreen,
            _ => Color.Grey
        };
        
        ColorConsole.WriteColored($"Password strength: {strength.Level}", color);
        
        if (strength.Suggestions.Any())
        {
            ColorConsole.WriteInfo("Suggestions for improvement:");
            foreach (var suggestion in strength.Suggestions)
            {
                ColorConsole.WriteInfo($"  • {suggestion}");
            }
        }
    }

    /// <summary>
    /// Prompts for a single password without confirmation.
    /// </summary>
    /// <param name="prompt">The prompt message.</param>
    /// <param name="allowEmpty">Whether to allow empty passwords.</param>
    /// <param name="minimumLength">Minimum password length.</param>
    /// <returns>The password as a UTF-8 byte array.</returns>
    private static byte[] PromptForSinglePassword(string prompt, bool allowEmpty, int minimumLength)
    {
        var textPrompt = new TextPrompt<string>($"[yellow]{prompt}:[/]")
            .Secret()
            .ShowDefaultValue(false);

        if (!allowEmpty || minimumLength > 0)
        {
            textPrompt.Validate(input =>
            {
                if (!allowEmpty && string.IsNullOrEmpty(input))
                {
                    return ValidationResult.Error("Password cannot be empty");
                }
                
                if (minimumLength > 0 && input.Length < minimumLength)
                {
                    return ValidationResult.Error($"Password must be at least {minimumLength} characters long");
                }
                
                return ValidationResult.Success();
            });
        }

        var passwordString = textPrompt.Show(AnsiConsole.Console);
        var passwordBytes = Encoding.UTF8.GetBytes(passwordString);
        
        // Clear the string from memory (best effort)
        if (passwordString.Length > 0)
        {
            unsafe
            {
                fixed (char* ptr = passwordString)
                {
                    for (int i = 0; i < passwordString.Length; i++)
                    {
                        ptr[i] = '\0';
                    }
                }
            }
        }
        
        return passwordBytes;
    }

    /// <summary>
    /// Compares two password byte arrays for equality in constant time.
    /// </summary>
    /// <param name="password1">First password.</param>
    /// <param name="password2">Second password.</param>
    /// <returns>True if passwords are equal, false otherwise.</returns>
    private static bool ArePasswordsEqual(byte[] password1, byte[] password2)
    {
        if (password1.Length != password2.Length)
        {
            return false;
        }

        int result = 0;
        for (int i = 0; i < password1.Length; i++)
        {
            result |= password1[i] ^ password2[i];
        }

        return result == 0;
    }

    /// <summary>
    /// Analyzes password strength and provides suggestions.
    /// </summary>
    /// <param name="password">The password to analyze.</param>
    /// <returns>Password strength analysis result.</returns>
    private static PasswordStrengthResult AnalyzePasswordStrength(string password)
    {
        var suggestions = new List<string>();
        var score = 0;

        // Length scoring
        if (password.Length >= 12)
            score += 2;
        else if (password.Length >= 8)
            score += 1;
        else
            suggestions.Add("Use at least 8 characters (12+ recommended)");

        // Character variety scoring
        bool hasLower = password.Any(char.IsLower);
        bool hasUpper = password.Any(char.IsUpper);
        bool hasDigit = password.Any(char.IsDigit);
        bool hasSymbol = password.Any(c => !char.IsLetterOrDigit(c));

        var charTypes = 0;
        if (hasLower) charTypes++;
        if (hasUpper) charTypes++;
        if (hasDigit) charTypes++;
        if (hasSymbol) charTypes++;

        score += charTypes;

        if (charTypes < 3)
        {
            if (!hasLower) suggestions.Add("Add lowercase letters");
            if (!hasUpper) suggestions.Add("Add uppercase letters");
            if (!hasDigit) suggestions.Add("Add numbers");
            if (!hasSymbol) suggestions.Add("Add special characters");
        }

        // Common patterns (reduce score)
        if (IsCommonPassword(password))
        {
            score -= 2;
            suggestions.Add("Avoid common passwords");
        }

        if (HasRepeatingPatterns(password))
        {
            score -= 1;
            suggestions.Add("Avoid repeating patterns");
        }

        // Determine strength level
        var level = score switch
        {
            <= 1 => PasswordStrengthLevel.VeryWeak,
            2 => PasswordStrengthLevel.Weak,
            3 => PasswordStrengthLevel.Fair,
            4 => PasswordStrengthLevel.Good,
            _ => PasswordStrengthLevel.Excellent
        };

        return new PasswordStrengthResult(level, suggestions.ToArray());
    }

    /// <summary>
    /// Checks if a password is commonly used.
    /// </summary>
    /// <param name="password">The password to check.</param>
    /// <returns>True if the password is common, false otherwise.</returns>
    private static bool IsCommonPassword(string password)
    {
        var common = new[]
        {
            "password", "123456", "password123", "admin", "qwerty",
            "letmein", "welcome", "monkey", "1234567890", "abc123"
        };
        
        return common.Contains(password.ToLowerInvariant());
    }

    /// <summary>
    /// Checks if a password has obvious repeating patterns.
    /// </summary>
    /// <param name="password">The password to check.</param>
    /// <returns>True if repeating patterns are found, false otherwise.</returns>
    private static bool HasRepeatingPatterns(string password)
    {
        if (password.Length < 3) return false;

        // Check for repeated characters (aaa, 111, etc.)
        for (int i = 0; i < password.Length - 2; i++)
        {
            if (password[i] == password[i + 1] && password[i + 1] == password[i + 2])
            {
                return true;
            }
        }

        // Check for keyboard patterns (qwerty, 12345, etc.)
        var keyboardPatterns = new[] { "qwerty", "asdf", "zxcv", "12345", "abcde" };
        var lowerPassword = password.ToLowerInvariant();
        
        return keyboardPatterns.Any(pattern => 
            lowerPassword.Contains(pattern) || lowerPassword.Contains(new string(pattern.Reverse().ToArray())));
    }
}

/// <summary>
/// Represents the strength level of a password.
/// </summary>
public enum PasswordStrengthLevel
{
    VeryWeak,
    Weak,
    Fair,
    Good,
    Excellent
}

/// <summary>
/// Represents the result of a password strength analysis.
/// </summary>
public class PasswordStrengthResult
{
    /// <summary>
    /// Gets the strength level of the password.
    /// </summary>
    public PasswordStrengthLevel Level { get; }

    /// <summary>
    /// Gets suggestions for improving the password.
    /// </summary>
    public string[] Suggestions { get; }

    /// <summary>
    /// Initializes a new instance of the PasswordStrengthResult class.
    /// </summary>
    /// <param name="level">The strength level.</param>
    /// <param name="suggestions">The suggestions for improvement.</param>
    public PasswordStrengthResult(PasswordStrengthLevel level, string[] suggestions)
    {
        Level = level;
        Suggestions = suggestions ?? Array.Empty<string>();
    }
}