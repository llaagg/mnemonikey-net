using System;
using System.CommandLine;
using System.CommandLine.Invocation;
using System.IO;
using System.Threading.Tasks;
using MnemonikeyCs.Cli.Interactive;
using MnemonikeyCs.Cli.Output;
using MnemonikeyCs.Cli.Validation;
using MnemonikeyCs.Pgp;
using MnemonikeyCs.Mnemonic;

namespace MnemonikeyCs.Cli.Commands;

/// <summary>
/// Command for generating new PGP keys with mnemonic recovery phrases.
/// </summary>
public class GenerateCommand : Command
{
    public GenerateCommand() : base("generate", "Generate a new PGP key with recovery phrase")
    {
        // Required options
        var nameOption = new Option<string>(
            aliases: new[] { "--name", "-n" },
            description: "User's full name");
        nameOption.IsRequired = true;

        var emailOption = new Option<string>(
            aliases: new[] { "--email", "-e" },
            description: "User's email address");
        emailOption.IsRequired = true;

        // Optional duration option
        var ttlOption = new Option<string>(
            aliases: new[] { "--ttl", "-t" },
            getDefaultValue: () => "2y",
            description: "Key validity period (e.g., 1y, 6m, 30d)");

        // Encryption options
        var encryptPhraseOption = new Option<bool>(
            aliases: new[] { "--encrypt-phrase" },
            getDefaultValue: () => false,
            description: "Generate encrypted recovery phrase (prompts for password)");

        var encryptKeysOption = new Option<bool>(
            aliases: new[] { "--encrypt-keys" },
            getDefaultValue: () => false,
            description: "Password-protect the generated PGP keys");

        // Output options
        var outputOption = new Option<string?>(
            aliases: new[] { "--output", "-o" },
            description: "Save PGP keys to file (default: stdout)");

        var binaryOption = new Option<bool>(
            aliases: new[] { "--binary" },
            getDefaultValue: () => false,
            description: "Output keys in binary format instead of ASCII armor");

        // Subkey index options
        var signingIndexOption = new Option<ushort>(
            aliases: new[] { "--signing-index" },
            getDefaultValue: () => 0,
            description: "Subkey index for signing key (default: 0)");

        var encryptionIndexOption = new Option<ushort>(
            aliases: new[] { "--encryption-index" },
            getDefaultValue: () => 0,
            description: "Subkey index for encryption key (default: 0)");

        var authIndexOption = new Option<ushort>(
            aliases: new[] { "--auth-index" },
            getDefaultValue: () => 0,
            description: "Subkey index for authentication key (default: 0)");

        // Force option for overwriting files
        var forceOption = new Option<bool>(
            aliases: new[] { "--force", "-f" },
            getDefaultValue: () => false,
            description: "Overwrite output file if it exists");

        // Add all options
        AddOption(nameOption);
        AddOption(emailOption);
        AddOption(ttlOption);
        AddOption(encryptPhraseOption);
        AddOption(encryptKeysOption);
        AddOption(outputOption);
        AddOption(binaryOption);
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
                var ttl = context.ParseResult.GetValueForOption(ttlOption)!;
                var encryptPhrase = context.ParseResult.GetValueForOption(encryptPhraseOption);
                var encryptKeys = context.ParseResult.GetValueForOption(encryptKeysOption);
                var output = context.ParseResult.GetValueForOption(outputOption);
                var binary = context.ParseResult.GetValueForOption(binaryOption);
                var signingIndex = context.ParseResult.GetValueForOption(signingIndexOption);
                var encryptionIndex = context.ParseResult.GetValueForOption(encryptionIndexOption);
                var authIndex = context.ParseResult.GetValueForOption(authIndexOption);
                var force = context.ParseResult.GetValueForOption(forceOption);
                var verbose = context.ParseResult.GetValueForOption(Program.GetVerboseOption());

                await ExecuteAsync(name, email, ttl, encryptPhrase, encryptKeys,
                    output, binary, signingIndex, encryptionIndex, authIndex, force, verbose);
            }
            catch (OperationCanceledException)
            {
                ColorConsole.WriteWarning("Operation cancelled by user.");
                Environment.Exit(1);
            }
            catch (Exception ex)
            {
                ColorConsole.WriteError($"Key generation failed: {ex.Message}");
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
        string ttl,
        bool encryptPhrase,
        bool encryptKeys,
        string? output,
        bool binary,
        ushort signingIndex,
        ushort encryptionIndex,
        ushort authIndex,
        bool force,
        bool verbose)
    {
        // Validate inputs
        await ValidateInputsAsync(name, email, ttl, output, force, verbose);

        // Show confirmation
        if (!ConfirmationPrompt.ConfirmKeyGeneration())
        {
            ColorConsole.WriteWarning("Key generation cancelled.");
            return;
        }

        // Parse TTL
        var ttlResult = DurationValidator.ValidateDuration(ttl);
        if (!ttlResult.IsValid)
        {
            throw new ArgumentException(ttlResult.ErrorMessage);
        }

        // Create User ID
        var userId = UserId.Create(name, email);
        
        // Set up PGP options
        var pgpOptions = new Mnemonikey.PgpOptions
        {
            EncryptionIndex = encryptionIndex,
            SigningIndex = signingIndex,
            AuthenticationIndex = authIndex,
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
        ColorConsole.WriteRule("🔐 Generating PGP Keys");

        string mnemonicPhrase = "";
        KeySet keySet = null!;

        // Generate keys with progress indication
        await ProgressIndicator.WithKeyGenerationProgressAsync(async () =>
        {
            await Task.Run(() =>
            {
                (mnemonicPhrase, keySet) = Mnemonikey.CreateNewPgpKey(userId.Value, pgpOptions);
            });
        }, "PGP key");

        ColorConsole.WriteSuccess("✅ PGP keys generated successfully!");
        ColorConsole.WriteLine();

        // Handle phrase encryption if requested
        string finalPhrase = mnemonicPhrase;
        if (encryptPhrase)
        {
            var phrasePassword = PasswordPrompt.PromptForPhrasePassword(forEncryption: true);
            
            try
            {
                ColorConsole.WriteInfo("Encrypting recovery phrase...");
                
                // Parse the existing phrase to get seed and creation time
                var (seed, creationTime) = Mnemonikey.DecodeMnemonic(mnemonicPhrase);
                
                // Create encrypted phrase
                var encryptedWords = MnemonicEncoder.EncodeToEncrypted(seed, creationTime, phrasePassword);
                finalPhrase = string.Join(" ", encryptedWords);
                
                ColorConsole.WriteSuccess("✅ Recovery phrase encrypted successfully!");
                
                // Clear sensitive data
                Array.Clear(phrasePassword, 0, phrasePassword.Length);
                seed.Dispose();
            }
            catch (Exception ex)
            {
                ColorConsole.WriteError($"Failed to encrypt phrase: {ex.Message}");
                throw;
            }
        }

        // Display results
        await DisplayResultsAsync(finalPhrase, keySet, encryptPhrase, output, verbose);

        // Export keys
        await ExportKeysAsync(keySet, pgpOptions, output, binary, force, verbose);

        // Security reminder
        ShowSecurityReminder(encryptPhrase, encryptKeys);

        // Clean up sensitive data
        if (keyPassword != null)
        {
            Array.Clear(keyPassword, 0, keyPassword.Length);
        }

        ColorConsole.WriteSuccess("🎉 Key generation completed successfully!");
    }

    private static Task ValidateInputsAsync(string name, string email, string ttl,
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

        // Validate TTL
        var ttlValidation = DurationValidator.ValidateDuration(ttl);
        if (!ttlValidation.IsValid)
        {
            throw new ArgumentException(ttlValidation.ErrorMessage);
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

    private static Task DisplayResultsAsync(string phrase, KeySet keySet,
        bool isEncrypted, string? output, bool verbose)
    {
        ColorConsole.WriteRule("📋 Generation Results");

        // Display key information
        TableFormatter.DisplayKeySetInfo(keySet, "Generated PGP Key");
        ColorConsole.WriteLine();

        // Display mnemonic phrase
        var phraseType = isEncrypted ? "Encrypted Recovery Phrase" : "Recovery Phrase";
        
        if (string.IsNullOrEmpty(output) || verbose)
        {
            if (ConfirmationPrompt.ConfirmSensitiveOutput("recovery phrase"))
            {
                var words = phrase.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                TableFormatter.DisplayMnemonicWords(words, phraseType, showNumbers: true);
            }
        }

        if (isEncrypted)
        {
            TableFormatter.DisplayWarningBox("🔐 Encrypted Phrase Notice",
                "This recovery phrase is encrypted and requires a password to use.",
                "Store both the phrase and password securely.",
                "If you lose the password, the phrase cannot be decrypted.");
        }
        else
        {
            TableFormatter.DisplayWarningBox("📝 Recovery Phrase Security",
                "This recovery phrase is not encrypted.",
                "Anyone with this phrase can recover your PGP keys.",
                "Store it securely and consider using --encrypt-phrase for additional security.");
        }

        // Confirm backup
        if (!ConfirmationPrompt.ConfirmPhraseBackup())
        {
            ColorConsole.WriteError("⚠️  Key generation completed, but phrase backup not confirmed.");
            ColorConsole.WriteError("Make sure to store your recovery phrase safely!");
        }
        
        return Task.CompletedTask;
    }

    private static async Task ExportKeysAsync(KeySet keySet, Mnemonikey.PgpOptions options,
        string? output, bool binary, bool force, bool verbose)
    {
        if (verbose)
        {
            ColorConsole.WriteInfo("Exporting keys...");
        }

        // Export keys
        string keyData;
        byte[] binaryData = null!;
        if (binary)
        {
            binaryData = Mnemonikey.ExportPgpBinary(keySet, options);
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
            if (ConfirmationPrompt.ConfirmSensitiveOutput("private keys"))
            {
                ColorConsole.WriteRule("🔑 PGP Keys");
                ColorConsole.WriteInfo(keyData);
            }
        }
    }

    private static void ShowSecurityReminder(bool encryptedPhrase, bool encryptedKeys)
    {
        ColorConsole.WriteLine();
        ColorConsole.WriteRule("🔒 Security Reminders");

        var reminders = new List<string>
        {
            "✅ Store your recovery phrase in a secure location",
            "✅ Consider making multiple copies in different secure locations",
            "✅ Never share your private keys or recovery phrase",
            "✅ Test key recovery periodically to ensure your backup works"
        };

        if (encryptedPhrase)
        {
            reminders.Add("🔐 Remember your recovery phrase password - it cannot be recovered if lost");
        }

        if (encryptedKeys)
        {
            reminders.Add("🔑 Remember your PGP key password - it's required to use your private keys");
        }

        if (!encryptedPhrase)
        {
            reminders.Add("⚠️  Consider using --encrypt-phrase for additional security");
        }

        if (!encryptedKeys)
        {
            reminders.Add("⚠️  Consider using --encrypt-keys to password-protect your private keys");
        }

        foreach (var reminder in reminders)
        {
            ColorConsole.WriteInfo(reminder);
        }
    }
}