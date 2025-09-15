using System;
using System.CommandLine;
using System.CommandLine.Invocation;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using MnemonikeyCs.Cli.Interactive;
using MnemonikeyCs.Cli.Output;
using MnemonikeyCs.Cli.Validation;
using MnemonikeyCs.Core;
using MnemonikeyCs.Pgp;
using MnemonikeyCs.Mnemonic;

namespace MnemonikeyCs.Cli.Commands;

/// <summary>
/// Command for recovering PGP keys from mnemonic recovery phrases.
/// </summary>
public class RecoverCommand : Command
{
    public RecoverCommand() : base("recover", "Recover PGP key from recovery phrase")
    {
        // Required options
        var nameOption = new Option<string>(
            aliases: new[] { "--name", "-n" },
            description: "User's full name (must match original)");
        nameOption.IsRequired = true;

        var emailOption = new Option<string>(
            aliases: new[] { "--email", "-e" },
            description: "User's email address (must match original)");
        emailOption.IsRequired = true;

        // Recovery phrase option
        var phraseOption = new Option<string[]?>(
            aliases: new[] { "--phrase", "-p" },
            description: "Recovery phrase as command line arguments");

        // Encryption options
        var encryptKeysOption = new Option<bool>(
            aliases: new[] { "--encrypt-keys" },
            getDefaultValue: () => false,
            description: "Password-protect the recovered PGP keys");

        // Output options
        var outputOption = new Option<string?>(
            aliases: new[] { "--output", "-o" },
            description: "Save PGP keys to file (default: stdout)");

        var binaryOption = new Option<bool>(
            aliases: new[] { "--binary" },
            getDefaultValue: () => false,
            description: "Output keys in binary format instead of ASCII armor");

        // Key type filter option
        var onlyOption = new Option<string?>(
            aliases: new[] { "--only" },
            description: "Only recover specific key type (signing, encryption, auth)");

        // Subkey index options
        var signingIndexOption = new Option<ushort?>(
            aliases: new[] { "--signing-index" },
            description: "Custom subkey index for signing (overrides default)");

        var encryptionIndexOption = new Option<ushort?>(
            aliases: new[] { "--encryption-index" },
            description: "Custom subkey index for encryption (overrides default)");

        var authIndexOption = new Option<ushort?>(
            aliases: new[] { "--auth-index" },
            description: "Custom subkey index for authentication (overrides default)");

        // Force option for overwriting files
        var forceOption = new Option<bool>(
            aliases: new[] { "--force", "-f" },
            getDefaultValue: () => false,
            description: "Overwrite output file if it exists");

        // Add all options
        AddOption(nameOption);
        AddOption(emailOption);
        AddOption(phraseOption);
        AddOption(encryptKeysOption);
        AddOption(outputOption);
        AddOption(binaryOption);
        AddOption(onlyOption);
        AddOption(signingIndexOption);
        AddOption(encryptionIndexOption);
        AddOption(authIndexOption);
        AddOption(forceOption);

        this.SetHandler(async (InvocationContext context) =>
        {
            try
            {
                var name = context.ParseResult.GetValueForOption(nameOption)!;
                var email = context.ParseResult.GetValueForOption(emailOption)!;
                var phrase = context.ParseResult.GetValueForOption(phraseOption);
                var encryptKeys = context.ParseResult.GetValueForOption(encryptKeysOption);
                var output = context.ParseResult.GetValueForOption(outputOption);
                var binary = context.ParseResult.GetValueForOption(binaryOption);
                var only = context.ParseResult.GetValueForOption(onlyOption);
                var signingIndex = context.ParseResult.GetValueForOption(signingIndexOption);
                var encryptionIndex = context.ParseResult.GetValueForOption(encryptionIndexOption);
                var authIndex = context.ParseResult.GetValueForOption(authIndexOption);
                var force = context.ParseResult.GetValueForOption(forceOption);
                var verbose = context.ParseResult.GetValueForOption(Program.GetVerboseOption());

                await ExecuteAsync(name, email, phrase, encryptKeys, output, binary,
                    only, signingIndex, encryptionIndex, authIndex, force, verbose);
            }
            catch (OperationCanceledException)
            {
                ColorConsole.WriteWarning("Operation cancelled by user.");
                Environment.Exit(1);
            }
            catch (Exception ex)
            {
                ColorConsole.WriteError($"Key recovery failed: {ex.Message}");
                var verbose = context.ParseResult.GetValueForOption(Program.GetVerboseOption());
                if (verbose)
                {
                    ColorConsole.WriteError(ex.ToString());
                }
                Environment.Exit(1);
            }
        });
    }

    private static async Task ExecuteAsync(
        string name,
        string email,
        string[]? phraseArgs,
        bool encryptKeys,
        string? output,
        bool binary,
        string? only,
        ushort? signingIndex,
        ushort? encryptionIndex,
        ushort? authIndex,
        bool force,
        bool verbose)
    {
        // Validate inputs
        await ValidateInputsAsync(name, email, only, output, force, verbose);

        // Show confirmation
        if (!ConfirmationPrompt.ConfirmKeyRecovery())
        {
            ColorConsole.WriteWarning("Key recovery cancelled.");
            return;
        }

        // Get recovery phrase
        string[] phraseWords;
        if (phraseArgs != null && phraseArgs.Length > 0)
        {
            phraseWords = phraseArgs;
            ColorConsole.WriteInfo($"Using phrase from command line ({phraseWords.Length} words).");
        }
        else
        {
            ColorConsole.WriteLine();
            phraseWords = WordInput.PromptForMnemonicPhrase();
        }

        // Validate phrase
        var phraseValidation = WordValidator.ValidatePhrase(string.Join(" ", phraseWords));
        if (!phraseValidation.IsValid)
        {
            throw new ArgumentException($"Invalid recovery phrase: {phraseValidation.ErrorMessage}");
        }

        var mnemonicPhrase = string.Join(" ", phraseValidation.ValidatedWords!);

        // Detect if phrase is encrypted
        bool isEncryptedPhrase;
        try
        {
            var version = MnemonicDecoder.DetectVersion(phraseValidation.ValidatedWords!);
            isEncryptedPhrase = version == MnemonicVersion.Encrypted;
            
            if (verbose)
            {
                ColorConsole.WriteInfo($"Detected {(isEncryptedPhrase ? "encrypted" : "plaintext")} recovery phrase.");
            }
        }
        catch (Exception ex)
        {
            throw new ArgumentException($"Could not detect phrase format: {ex.Message}");
        }

        // Handle encrypted phrase decryption
        string finalPhrase = mnemonicPhrase;
        if (isEncryptedPhrase)
        {
            var phrasePassword = PasswordPrompt.PromptForPhrasePassword(forEncryption: false);
            
            try
            {
                ColorConsole.WriteInfo("Decrypting recovery phrase...");
                
                // Decrypt the phrase
                var (seed, creationTime) = MnemonicDecoder.DecodeEncrypted(
                    phraseValidation.ValidatedWords!, phrasePassword);
                
                // Convert back to plaintext phrase
                finalPhrase = Mnemonikey.EncodeMnemonic(seed, creationTime);
                
                ColorConsole.WriteSuccess("✅ Recovery phrase decrypted successfully!");
                
                // Clear sensitive data
                Array.Clear(phrasePassword, 0, phrasePassword.Length);
                seed.Dispose();
            }
            catch (UnauthorizedAccessException)
            {
                throw new ArgumentException("Invalid password for encrypted recovery phrase.");
            }
            catch (Exception ex)
            {
                throw new ArgumentException($"Failed to decrypt phrase: {ex.Message}");
            }
        }

        // Create User ID
        var userId = UserId.Create(name, email);
        
        // Set up PGP options
        var pgpOptions = new Mnemonikey.PgpOptions
        {
            EncryptionIndex = encryptionIndex ?? Mnemonikey.DefaultOptions.EncryptionIndex,
            SigningIndex = signingIndex ?? Mnemonikey.DefaultOptions.SigningIndex,
            AuthenticationIndex = authIndex ?? Mnemonikey.DefaultOptions.AuthenticationIndex,
            IncludePrivateKeys = true
        };

        // Get password for key encryption if needed
        byte[]? keyPassword = null;
        if (encryptKeys)
        {
            keyPassword = PasswordPrompt.PromptForPgpPassword(forEncryption: true);
            pgpOptions.Password = System.Text.Encoding.UTF8.GetString(keyPassword);
        }

        ColorConsole.WriteLine();
        ColorConsole.WriteRule("🔐 Recovering PGP Keys");

        KeySet keySet = null!;

        // Recover keys with progress indication
        await ProgressIndicator.WithKeyGenerationProgressAsync(async () =>
        {
            await Task.Run(() =>
            {
                keySet = Mnemonikey.GeneratePgpKeySet(finalPhrase, userId.Value, pgpOptions);
            });
        }, "PGP key recovery");

        ColorConsole.WriteSuccess("✅ PGP keys recovered successfully!");
        ColorConsole.WriteLine();

        // Display results
        await DisplayResultsAsync(keySet, finalPhrase, isEncryptedPhrase, output, only, verbose);

        // Export keys based on 'only' filter
        await ExportKeysAsync(keySet, pgpOptions, output, binary, force, only, verbose);

        // Clean up sensitive data
        if (keyPassword != null)
        {
            Array.Clear(keyPassword, 0, keyPassword.Length);
        }

        ColorConsole.WriteSuccess("🎉 Key recovery completed successfully!");
    }

    private static Task ValidateInputsAsync(string name, string email, string? only,
        string? output, bool force, bool verbose)
    {
        if (verbose)
        {
            ColorConsole.WriteInfo("Validating inputs...");
        }

        // Validate name
        if (string.IsNullOrWhiteSpace(name))
        {
            throw new ArgumentException("Name cannot be empty.");
        }

        if (name.Length > 255)
        {
            throw new ArgumentException("Name is too long (maximum 255 characters).");
        }

        // Validate email
        var emailValidation = EmailValidator.ValidateEmail(email);
        if (!emailValidation.IsValid)
        {
            var suggestion = EmailValidator.SuggestCorrection(email);
            var message = emailValidation.ErrorMessage;
            if (!string.IsNullOrEmpty(suggestion))
            {
                message += $" Did you mean: {suggestion}?";
            }
            throw new ArgumentException(message);
        }

        // Validate 'only' option
        if (!string.IsNullOrEmpty(only))
        {
            var validOptions = new[] { "signing", "encryption", "auth" };
            if (!validOptions.Contains(only.ToLowerInvariant()))
            {
                throw new ArgumentException($"Invalid --only option. Valid values: {string.Join(", ", validOptions)}");
            }
        }

        // Validate output file
        if (!string.IsNullOrEmpty(output))
        {
            var directory = Path.GetDirectoryName(output);
            if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
            {
                throw new ArgumentException($"Output directory does not exist: {directory}");
            }

            if (File.Exists(output) && !force)
            {
                if (!ConfirmationPrompt.ConfirmFileOverwrite(output))
                {
                    throw new OperationCanceledException("Output file exists and overwrite was not confirmed.");
                }
            }
        }

        if (verbose)
        {
            ColorConsole.WriteSuccess("✅ Input validation passed.");
        }
        
        return Task.CompletedTask;
    }

    private static Task DisplayResultsAsync(KeySet keySet, string originalPhrase,
        bool wasEncrypted, string? output, string? only, bool verbose)
    {
        ColorConsole.WriteRule("📋 Recovery Results");

        // Display key information
        var title = string.IsNullOrEmpty(only) ? "Recovered PGP Key" : $"Recovered PGP Key ({only} only)";
        TableFormatter.DisplayKeySetInfo(keySet, title);
        ColorConsole.WriteLine();

        // Display information about the original phrase
        if (verbose || string.IsNullOrEmpty(output))
        {
            try
            {
                var info = Mnemonikey.GetMnemonicInfo(originalPhrase);
                TableFormatter.DisplayMnemonicInfo(originalPhrase, info, "Original Recovery Phrase Info");
            }
            catch (Exception ex)
            {
                if (verbose)
                {
                    ColorConsole.WriteWarning($"Could not analyze original phrase: {ex.Message}");
                }
            }
        }

        if (wasEncrypted)
        {
            TableFormatter.DisplayInfoBox("🔓 Decrypted Phrase",
                "The recovery phrase was successfully decrypted.",
                "The recovered keys match the original encrypted phrase.");
        }

        // Show warning about key consistency
        TableFormatter.DisplayWarningBox("🔍 Key Consistency",
            "Ensure the name and email match exactly what was used during generation.",
            "Different user information will generate different keys.",
            "Custom subkey indices must match the original generation settings.");
            
        return Task.CompletedTask;
    }

    private static async Task ExportKeysAsync(KeySet keySet, Mnemonikey.PgpOptions options,
        string? output, bool binary, bool force, string? only, bool verbose)
    {
        if (verbose)
        {
            ColorConsole.WriteInfo("Exporting keys...");
        }

        // Filter keys based on 'only' option
        if (!string.IsNullOrEmpty(only))
        {
            // Note: This is a simplified implementation
            // In a real scenario, you might want to export only specific subkeys
            ColorConsole.WriteWarning("Note: --only option exports the complete key set.");
            ColorConsole.WriteWarning($"Use key management tools to extract {only} subkey if needed.");
        }

        // Export keys
        string keyData;
        if (binary)
        {
            var binaryData = Mnemonikey.ExportPgpBinary(keySet, options);
            keyData = Convert.ToBase64String(binaryData);
        }
        else
        {
            keyData = Mnemonikey.ExportPgpArmored(keySet, options);
        }

        // Output to file or console
        if (!string.IsNullOrEmpty(output))
        {
            if (binary)
            {
                var binaryData = Mnemonikey.ExportPgpBinary(keySet, options);
                await File.WriteAllBytesAsync(output, binaryData);
            }
            else
            {
                await File.WriteAllTextAsync(output, keyData);
            }

            ColorConsole.WriteSuccess($"✅ Keys saved to: {output}");
        }
        else
        {
            if (ConfirmationPrompt.ConfirmSensitiveOutput("recovered private keys"))
            {
                ColorConsole.WriteRule("🔑 Recovered PGP Keys");
                ColorConsole.WriteInfo(keyData);
            }
        }
    }
}