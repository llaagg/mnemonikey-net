using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xunit;
using Xunit.Abstractions;
using MnemonikeyCs.Core;
using MnemonikeyCs.Pgp;

namespace MnemonikeyCs.Tests.Pgp;

/// <summary>
/// Tests for interoperability with GPG command-line tool.
/// These tests verify that keys generated with MnemonikeyCs can be imported
/// into GPG and used for encryption/decryption operations.
/// </summary>
public class GpgInteropTests : TestBase
{
    public GpgInteropTests(ITestOutputHelper output) : base(output) { }

    private static bool IsGpgAvailable()
    {
        try
        {
            var process = Process.Start(new ProcessStartInfo
            {
                FileName = "gpg",
                Arguments = "--version",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            });
            
            if (process == null) return false;
            
            process.WaitForExit();
            return process.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }

    [Fact]
    public async Task ImportIntoGPG_WithArmoredKey_Succeeds()
    {
        if (!IsGpgAvailable())
        {
            Output.WriteLine("GPG not available, skipping test");
            return;
        }

        // Arrange
        var seed = Seed.GenerateRandom();
        var userId = UserId.Create("GPG Test User", "gpgtest@example.com");
        var password = "test-password-123";
        
        using var keySet = KeySet.Create(seed, userId);
        var armoredPrivateKey = keySet.ExportPrivateKeyArmored(password);
        var keyIdHex = BitConverter.ToString(keySet.KeyId).Replace("-", "");
        
        Output.WriteLine($"Key ID: {keyIdHex}");

        // Create temp directory for GPG home
        var tempDir = Path.Combine(Path.GetTempPath(), "gpg-test-" + Guid.NewGuid().ToString());
        Directory.CreateDirectory(tempDir);
        
        try
        {
            // Import key into GPG
            var keyFile = Path.Combine(tempDir, "key.asc");
            await File.WriteAllTextAsync(keyFile, armoredPrivateKey);
            
            var importProcess = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "gpg",
                    Arguments = $"--homedir \"{tempDir}\" --batch --import \"{keyFile}\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };
            
            importProcess.Start();
            var output = await importProcess.StandardOutput.ReadToEndAsync();
            var error = await importProcess.StandardError.ReadToEndAsync();
            await importProcess.WaitForExitAsync();
            
            Output.WriteLine("GPG Import Output:");
            Output.WriteLine(output);
            if (!string.IsNullOrEmpty(error))
            {
                Output.WriteLine("GPG Import Errors/Warnings:");
                Output.WriteLine(error);
            }
            
            // Assert - import succeeded
            Assert.Equal(0, importProcess.ExitCode);
            
            // Verify key is in keyring
            var listProcess = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "gpg",
                    Arguments = $"--homedir \"{tempDir}\" --list-keys",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };
            
            listProcess.Start();
            var listOutput = await listProcess.StandardOutput.ReadToEndAsync();
            await listProcess.WaitForExitAsync();
            
            Output.WriteLine("GPG List Keys Output:");
            Output.WriteLine(listOutput);
            
            Assert.Contains(userId.Email ?? string.Empty, listOutput);
            Output.WriteLine("✓ Key successfully imported into GPG!");
        }
        finally
        {
            if (Directory.Exists(tempDir))
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }
    }

    [Fact]
    public async Task EncryptAndDecrypt_WithGPG_WorksCorrectly()
    {
        if (!IsGpgAvailable())
        {
            Output.WriteLine("GPG not available, skipping test");
            return;
        }

        // Arrange
        var seed = Seed.GenerateRandom();
        var userId = UserId.Create("Encryption Test", "encrypt@example.com");
        var password = "encryption-password";
        
        using var keySet = KeySet.Create(seed, userId);
        var armoredPrivateKey = keySet.ExportPrivateKeyArmored(password);
        var armoredPublicKey = keySet.ExportPublicKeyArmored();
        
        var tempDir = Path.Combine(Path.GetTempPath(), "gpg-test-" + Guid.NewGuid().ToString());
        Directory.CreateDirectory(tempDir);
        
        try
        {
            // Import keys
            var privateKeyFile = Path.Combine(tempDir, "private.asc");
            var publicKeyFile = Path.Combine(tempDir, "public.asc");
            await File.WriteAllTextAsync(privateKeyFile, armoredPrivateKey);
            await File.WriteAllTextAsync(publicKeyFile, armoredPublicKey);
            
            var importPriv = Process.Start(new ProcessStartInfo
            {
                FileName = "gpg",
                Arguments = $"--homedir \"{tempDir}\" --batch --import \"{privateKeyFile}\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            });
            await importPriv!.WaitForExitAsync();
            
            // Create test message
            var messageFile = Path.Combine(tempDir, "message.txt");
            var testMessage = "This is a secret message!";
            await File.WriteAllTextAsync(messageFile, testMessage);
            
            // Encrypt with public key
            var encryptedFile = Path.Combine(tempDir, "message.txt.gpg");
            var encryptProcess = Process.Start(new ProcessStartInfo
            {
                FileName = "gpg",
                Arguments = $"--homedir \"{tempDir}\" --batch --trust-model always --recipient \"{userId.Email}\" --encrypt \"{messageFile}\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            });
            await encryptProcess!.WaitForExitAsync();
            
            Assert.Equal(0, encryptProcess.ExitCode);
            Assert.True(File.Exists(encryptedFile), "Encrypted file should exist");
            
            Output.WriteLine("✓ Message encrypted successfully with GPG");
            
            // Decrypt with private key
            var decryptedFile = Path.Combine(tempDir, "decrypted.txt");
            var decryptProcess = Process.Start(new ProcessStartInfo
            {
                FileName = "gpg",
                Arguments = $"--homedir \"{tempDir}\" --batch --pinentry-mode loopback --passphrase \"{password}\" --decrypt --output \"{decryptedFile}\" \"{encryptedFile}\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            });
            await decryptProcess!.WaitForExitAsync();
            
            Assert.Equal(0, decryptProcess.ExitCode);
            
            var decryptedMessage = await File.ReadAllTextAsync(decryptedFile);
            Assert.Equal(testMessage, decryptedMessage);
            
            Output.WriteLine($"✓ Message decrypted successfully: {decryptedMessage}");
        }
        finally
        {
            if (Directory.Exists(tempDir))
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }
    }
}
