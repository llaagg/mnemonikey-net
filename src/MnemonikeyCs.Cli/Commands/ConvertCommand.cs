using System;
using System.CommandLine;
using System.IO;
using System.Threading.Tasks;
using MnemonikeyCs.Cli.Interactive;
using MnemonikeyCs.Cli.Output;
using MnemonikeyCs.Cli.Validation;
using MnemonikeyCs.Core;
using MnemonikeyCs.Mnemonic;

namespace MnemonikeyCs.Cli.Commands;

/// <summary>
/// Command for converting between plaintext and encrypted mnemonic phrase formats.
/// </summary>
public class ConvertCommand : Command
{
    public ConvertCommand() : base("convert", "Convert between phrase formats")
    {
        // Phrase input option
        var phraseOption = new Option<string[]?>(
            aliases: new[] { "--phrase", "-p" },
            description: "Input recovery phrase as command line arguments");

        // Conversion direction options (mutually exclusive)
        var encryptPhraseOption = new Option<bool>(
            aliases: new[] { "--encrypt-phrase" },
            getDefaultValue: () => false,
            description: "Convert to encrypted phrase (prompts for password)");

        var decryptPhraseOption = new Option<bool>(
            aliases: new[] { "--decrypt-phrase" },
            getDefaultValue: () => false,
            description: "Convert to plaintext phrase (prompts for password)");

        // Output options
        var outputOption = new Option<string?>(
            aliases: new[] { "--output", "-o" },
            description: "Save converted phrase to file (default: stdout)");

        var forceOption = new Option<bool>(
            aliases: new[] { "--force", "-f" },
            getDefaultValue: () => false,
            description: "Overwrite output file if it exists");

        var showInfoOption = new Option<bool>(
            aliases: new[] { "--info", "-i" },
            getDefaultValue: () => false,
            description: "Show information about the phrase without converting");

        // Add all options
        AddOption(phraseOption);
        AddOption(encryptPhraseOption);
        AddOption(decryptPhraseOption);
        AddOption(outputOption);
        AddOption(forceOption);
        AddOption(showInfoOption);

        this.SetHandler(async (
            string[]? phrase,
            bool encryptPhrase,
            bool decryptPhrase,
            string? output,
            bool force,
            bool showInfo,
            bool verbose) =>
        {
            try
            {
                await ExecuteAsync(phrase, encryptPhrase, decryptPhrase, output, force, showInfo, verbose);
            }
            catch (OperationCanceledException)
            {
                ColorConsole.WriteWarning("Operation cancelled by user.");
                Environment.Exit(1);
            }
            catch (Exception ex)
            {
                ColorConsole.WriteError($"Phrase conversion failed: {ex.Message}");
                if (verbose)
                {
                    ColorConsole.WriteError(ex.ToString());
                }
                Environment.Exit(1);
            }
        },
        phraseOption, encryptPhraseOption, decryptPhraseOption, outputOption,
        forceOption, showInfoOption, Program.GetVerboseOption());
    }

    private static async Task ExecuteAsync(
        string[]? phraseArgs,
        bool encryptPhrase,
        bool decryptPhrase,
        string? output,
        bool force,
        bool showInfo,
        bool verbose)
    {
        // Validate inputs
        await ValidateInputsAsync(encryptPhrase, decryptPhrase, output, force, showInfo, verbose);

        // Get input phrase
        string[] phraseWords;
        if (phraseArgs != null && phraseArgs.Length > 0)
        {
            phraseWords = phraseArgs;
            ColorConsole.WriteInfo($"Using phrase from command line ({phraseWords.Length} words).");
        }
        else
        {
            ColorConsole.WriteLine();
            ColorConsole.WriteRule("📝 Enter Recovery Phrase");
            phraseWords = WordInput.PromptForMnemonicPhrase();
        }

        // Validate phrase
        var phraseValidation = WordValidator.ValidatePhrase(string.Join(" ", phraseWords));
        if (!phraseValidation.IsValid)
        {
            throw new ArgumentException($"Invalid recovery phrase: {phraseValidation.ErrorMessage}");
        }

        var inputPhrase = string.Join(" ", phraseValidation.ValidatedWords!);

        // Detect phrase format
        bool isInputEncrypted;
        try
        {
            var version = MnemonicDecoder.DetectVersion(phraseValidation.ValidatedWords!);
            isInputEncrypted = version == MnemonicVersion.Encrypted;
            
            if (verbose)
            {
                ColorConsole.WriteInfo($"Detected {(isInputEncrypted ? "encrypted" : "plaintext")} input phrase.");
            }
        }
        catch (Exception ex)
        {
            throw new ArgumentException($"Could not detect phrase format: {ex.Message}");
        }

        // Show phrase information if requested
        if (showInfo)
        {
            await ShowPhraseInfoAsync(inputPhrase, isInputEncrypted, phraseValidation.ValidatedWords!);
            return;
        }

        // Determine conversion direction
        bool shouldEncrypt = encryptPhrase || (!decryptPhrase && !isInputEncrypted);
        bool shouldDecrypt = decryptPhrase || (!encryptPhrase && isInputEncrypted);

        // If both or neither options are specified, use the opposite of current format
        if ((encryptPhrase && decryptPhrase) || (!encryptPhrase && !decryptPhrase))
        {
            shouldEncrypt = !isInputEncrypted;
            shouldDecrypt = isInputEncrypted;
        }

        // Validate conversion direction
        if (shouldEncrypt && isInputEncrypted)
        {
            throw new ArgumentException("Input phrase is already encrypted. Use --decrypt-phrase to decrypt it.");
        }

        if (shouldDecrypt && !isInputEncrypted)
        {
            throw new ArgumentException("Input phrase is already plaintext. Use --encrypt-phrase to encrypt it.");
        }

        // Show confirmation
        if (!ConfirmationPrompt.ConfirmPhraseConversion(!isInputEncrypted))
        {
            ColorConsole.WriteWarning("Phrase conversion cancelled.");
            return;
        }

        ColorConsole.WriteLine();

        string convertedPhrase;

        if (shouldEncrypt)
        {
            // Convert plaintext to encrypted
            convertedPhrase = await ConvertToEncryptedAsync(inputPhrase, verbose);
        }
        else
        {
            // Convert encrypted to plaintext
            convertedPhrase = await ConvertToPlaintextAsync(phraseValidation.ValidatedWords!, verbose);
        }

        // Display results
        await DisplayResultsAsync(inputPhrase, convertedPhrase, shouldEncrypt, output, verbose);

        // Save or output the converted phrase
        await SaveConvertedPhraseAsync(convertedPhrase, output, force, shouldEncrypt, verbose);

        ColorConsole.WriteSuccess("🎉 Phrase conversion completed successfully!");
    }

    private static Task ValidateInputsAsync(bool encryptPhrase, bool decryptPhrase,
        string? output, bool force, bool showInfo, bool verbose)
    {
        if (verbose)
        {
            ColorConsole.WriteInfo("Validating inputs...");
        }

        // If showing info, skip other validations
        if (showInfo)
        {
            if (encryptPhrase || decryptPhrase)
            {
                ColorConsole.WriteWarning("Conversion options ignored when --info is specified.");
            }
            return Task.CompletedTask;
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

    private static Task<string> ConvertToEncryptedAsync(string plaintextPhrase, bool verbose)
    {
        if (verbose)
        {
            ColorConsole.WriteInfo("Converting plaintext phrase to encrypted format...");
        }

        // Get password for encryption
        var password = PasswordPrompt.PromptForPhrasePassword(forEncryption: true);

        try
        {
            // Parse the plaintext phrase
            var (seed, creationTime) = Mnemonikey.DecodeMnemonic(plaintextPhrase);

            // Create encrypted phrase
            var encryptedWords = MnemonicEncoder.EncodeToEncrypted(seed, creationTime, password);
            var encryptedPhrase = string.Join(" ", encryptedWords);

            ColorConsole.WriteSuccess("✅ Phrase encrypted successfully!");

            // Clean up sensitive data
            Array.Clear(password, 0, password.Length);
            seed.Dispose();

            return Task.FromResult(encryptedPhrase);
        }
        catch (Exception ex)
        {
            // Clean up sensitive data on error
            Array.Clear(password, 0, password.Length);
            throw new InvalidOperationException($"Failed to encrypt phrase: {ex.Message}", ex);
        }
    }

    private static Task<string> ConvertToPlaintextAsync(string[] encryptedWords, bool verbose)
    {
        if (verbose)
        {
            ColorConsole.WriteInfo("Converting encrypted phrase to plaintext format...");
        }

        // Get password for decryption
        var password = PasswordPrompt.PromptForPhrasePassword(forEncryption: false);

        try
        {
            // Decrypt the phrase
            var (seed, creationTime) = MnemonicDecoder.DecodeEncrypted(encryptedWords, password);

            // Create plaintext phrase
            var plaintextPhrase = Mnemonikey.EncodeMnemonic(seed, creationTime);

            ColorConsole.WriteSuccess("✅ Phrase decrypted successfully!");

            // Clean up sensitive data
            Array.Clear(password, 0, password.Length);
            seed.Dispose();

            return Task.FromResult(plaintextPhrase);
        }
        catch (UnauthorizedAccessException)
        {
            Array.Clear(password, 0, password.Length);
            throw new ArgumentException("Invalid password for encrypted recovery phrase.");
        }
        catch (Exception ex)
        {
            Array.Clear(password, 0, password.Length);
            throw new InvalidOperationException($"Failed to decrypt phrase: {ex.Message}", ex);
        }
    }

    private static Task ShowPhraseInfoAsync(string phrase, bool isEncrypted, string[] words)
    {
        ColorConsole.WriteRule("📊 Recovery Phrase Information");

        try
        {
            if (!isEncrypted)
            {
                var info = Mnemonikey.GetMnemonicInfo(phrase);
                TableFormatter.DisplayMnemonicInfo(phrase, info, "Phrase Analysis");
                ColorConsole.WriteLine();
                
                // Display the words
                TableFormatter.DisplayMnemonicWords(words, "Recovery Phrase Words", showNumbers: true);
            }
            else
            {
                ColorConsole.WriteInfo($"Phrase Type: Encrypted ({words.Length} words)");
                ColorConsole.WriteInfo("Format: Encrypted mnemonic phrase requiring password");
                ColorConsole.WriteWarning("Cannot analyze encrypted phrases without decryption password.");
                ColorConsole.WriteLine();
                
                // Display the words without analysis
                TableFormatter.DisplayMnemonicWords(words, "Encrypted Recovery Phrase", showNumbers: true);
                
                ColorConsole.WriteInfo("To view detailed information, decrypt the phrase first:");
                ColorConsole.WriteInfo($"  {Program.AppName} convert --decrypt-phrase");
            }
        }
        catch (Exception ex)
        {
            ColorConsole.WriteError($"Failed to analyze phrase: {ex.Message}");
            
            // Fallback: just show basic information
            ColorConsole.WriteInfo($"Word Count: {words.Length}");
            ColorConsole.WriteInfo($"Format: {(isEncrypted ? "Encrypted" : "Plaintext")}");
        }

        // Show format information
        ColorConsole.WriteLine();
        TableFormatter.DisplayInfoBox("📋 Format Information",
            isEncrypted 
                ? "Encrypted phrases require a password to use and are 18 words long."
                : "Plaintext phrases do not require a password and are 15 words long.",
            isEncrypted 
                ? "Use --decrypt-phrase to convert to plaintext format."
                : "Use --encrypt-phrase to convert to encrypted format for additional security.");
        
        return Task.CompletedTask;
    }

    private static Task DisplayResultsAsync(string inputPhrase, string convertedPhrase,
        bool wasEncrypted, string? output, bool verbose)
    {
        ColorConsole.WriteRule("📋 Conversion Results");

        var inputWords = inputPhrase.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var outputWords = convertedPhrase.Split(' ', StringSplitOptions.RemoveEmptyEntries);

        // Show conversion summary
        ColorConsole.WriteInfo($"Converted from: {(wasEncrypted ? "Plaintext" : "Encrypted")} ({inputWords.Length} words)");
        ColorConsole.WriteInfo($"Converted to: {(wasEncrypted ? "Encrypted" : "Plaintext")} ({outputWords.Length} words)");
        ColorConsole.WriteLine();

        // Display converted phrase if not saving to file or if verbose
        if (string.IsNullOrEmpty(output) || verbose)
        {
            if (ConfirmationPrompt.ConfirmSensitiveOutput("converted recovery phrase"))
            {
                var title = wasEncrypted ? "Encrypted Recovery Phrase" : "Plaintext Recovery Phrase";
                TableFormatter.DisplayMnemonicWords(outputWords, title, showNumbers: true);
            }
        }

        // Show security warnings
        if (wasEncrypted)
        {
            TableFormatter.DisplayWarningBox("🔐 Encrypted Phrase Security",
                "This encrypted phrase requires a password to use.",
                "Store both the phrase and password securely.",
                "If you lose the password, the phrase cannot be decrypted.");
        }
        else
        {
            TableFormatter.DisplayWarningBox("📝 Plaintext Phrase Security",
                "This plaintext phrase is not password-protected.",
                "Anyone with this phrase can recover your PGP keys.",
                "Store it securely and consider keeping an encrypted backup.");
        }
        
        return Task.CompletedTask;
    }

    private static async Task SaveConvertedPhraseAsync(string convertedPhrase, string? output,
        bool force, bool wasEncrypted, bool verbose)
    {
        if (!string.IsNullOrEmpty(output))
        {
            await File.WriteAllTextAsync(output, convertedPhrase);
            ColorConsole.WriteSuccess($"✅ Converted phrase saved to: {output}");
        }
        else
        {
            // Output to console if not saving to file
            if (!ConfirmationPrompt.ConfirmSensitiveOutput("converted phrase"))
            {
                ColorConsole.WriteInfo("Phrase conversion completed but not displayed.");
                ColorConsole.WriteInfo("Use --output to save to file, or run again to display on console.");
            }
        }

        // Security reminders
        ColorConsole.WriteLine();
        ColorConsole.WriteRule("🔒 Security Reminders");
        
        if (wasEncrypted)
        {
            ColorConsole.WriteInfo("✅ Your phrase is now encrypted with a password");
            ColorConsole.WriteInfo("🔐 Remember your password - it cannot be recovered if lost");
            ColorConsole.WriteInfo("💾 Consider keeping both encrypted and plaintext backups in secure locations");
        }
        else
        {
            ColorConsole.WriteInfo("✅ Your phrase is now in plaintext format");
            ColorConsole.WriteInfo("⚠️  No password is required to use this phrase");
            ColorConsole.WriteInfo("🔒 Store it securely - anyone with access can recover your keys");
        }
    }
}