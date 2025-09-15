using System;
using System.ComponentModel;
using MnemonikeyCs.Core;
using MnemonikeyCs.Mnemonic;
using MnemonikeyCs.Pgp;

namespace MnemonikeyCs;

/// <summary>
/// The main Mnemonikey API providing deterministic key generation from mnemonic phrases.
/// This is a complete C# port of the Go mnemonikey library.
/// </summary>
public static class Mnemonikey
{
    /// <summary>
    /// Default options for PGP key generation.
    /// </summary>
    public static class DefaultOptions
    {
        /// <summary>
        /// Default encryption subkey index.
        /// </summary>
        public const ushort EncryptionIndex = 0;

        /// <summary>
        /// Default signing subkey index.
        /// </summary>
        public const ushort SigningIndex = 0;

        /// <summary>
        /// Default authentication subkey index.
        /// </summary>
        public const ushort AuthenticationIndex = 0;
    }

    /// <summary>
    /// Options for PGP key generation.
    /// </summary>
    public sealed class PgpOptions
    {
        /// <summary>
        /// Gets or sets the encryption subkey index for key cycling.
        /// </summary>
        public ushort EncryptionIndex { get; set; } = DefaultOptions.EncryptionIndex;

        /// <summary>
        /// Gets or sets the signing subkey index for key cycling.
        /// </summary>
        public ushort SigningIndex { get; set; } = DefaultOptions.SigningIndex;

        /// <summary>
        /// Gets or sets the authentication subkey index for key cycling.
        /// </summary>
        public ushort AuthenticationIndex { get; set; } = DefaultOptions.AuthenticationIndex;

        /// <summary>
        /// Gets or sets the password for encrypting private keys (null for unencrypted).
        /// </summary>
        public string? Password { get; set; }

        /// <summary>
        /// Gets or sets whether to include private key material in exports.
        /// </summary>
        public bool IncludePrivateKeys { get; set; } = true;

        /// <summary>
        /// Creates default PGP options.
        /// </summary>
        /// <returns>Default PGP options.</returns>
        public static PgpOptions Default() => new();

        /// <summary>
        /// Creates PGP options with custom subkey indices.
        /// </summary>
        /// <param name="encryptionIndex">Encryption subkey index.</param>
        /// <param name="signingIndex">Signing subkey index.</param>
        /// <param name="authenticationIndex">Authentication subkey index.</param>
        /// <returns>PGP options with custom indices.</returns>
        public static PgpOptions WithIndices(ushort encryptionIndex, ushort signingIndex, ushort authenticationIndex)
        {
            return new PgpOptions
            {
                EncryptionIndex = encryptionIndex,
                SigningIndex = signingIndex,
                AuthenticationIndex = authenticationIndex
            };
        }

        /// <summary>
        /// Creates PGP options with password protection.
        /// </summary>
        /// <param name="password">The password for private key encryption.</param>
        /// <returns>PGP options with password protection.</returns>
        public static PgpOptions WithPassword(string password)
        {
            ArgumentNullException.ThrowIfNull(password);
            return new PgpOptions { Password = password };
        }

        /// <summary>
        /// Creates PGP options for public key only export.
        /// </summary>
        /// <returns>PGP options for public key export.</returns>
        public static PgpOptions PublicOnly()
        {
            return new PgpOptions { IncludePrivateKeys = false };
        }
    }

    /// <summary>
    /// Encodes a seed as a mnemonic phrase.
    /// </summary>
    /// <param name="seed">The seed to encode.</param>
    /// <param name="creationTime">The key creation time.</param>
    /// <returns>The mnemonic phrase.</returns>
    /// <exception cref="ArgumentNullException">Thrown when seed is null.</exception>
    public static string EncodeMnemonic(Seed seed, DateTime creationTime)
    {
        ArgumentNullException.ThrowIfNull(seed);
        
        return string.Join(" ", MnemonicEncoder.EncodeToPlaintext(seed, creationTime));
    }

    /// <summary>
    /// Decodes a mnemonic phrase to extract the seed and creation time.
    /// </summary>
    /// <param name="mnemonicPhrase">The mnemonic phrase.</param>
    /// <returns>A tuple containing the decoded seed and creation time.</returns>
    /// <exception cref="ArgumentException">Thrown when the mnemonic phrase is invalid.</exception>
    public static (Seed seed, DateTime creationTime) DecodeMnemonic(string mnemonicPhrase)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(mnemonicPhrase);
        
        return MnemonicDecoder.DecodePlaintext(mnemonicPhrase.Split(' ', StringSplitOptions.RemoveEmptyEntries));
    }

    /// <summary>
    /// Generates a random seed.
    /// </summary>
    /// <returns>A new random seed.</returns>
    public static Seed GenerateRandomSeed()
    {
        return Seed.GenerateRandom();
    }

    /// <summary>
    /// Creates a seed from a hexadecimal string.
    /// </summary>
    /// <param name="hex">The hexadecimal string.</param>
    /// <returns>A seed created from the hex string.</returns>
    /// <exception cref="ArgumentException">Thrown when the hex string is invalid.</exception>
    public static Seed CreateSeedFromHex(string hex)
    {
        return Seed.FromHex(hex);
    }

    /// <summary>
    /// Generates a complete PGP key set from a mnemonic phrase.
    /// </summary>
    /// <param name="mnemonicPhrase">The mnemonic phrase.</param>
    /// <param name="userId">The User ID for the key.</param>
    /// <param name="options">Optional PGP generation options.</param>
    /// <returns>A complete PGP key set.</returns>
    /// <exception cref="ArgumentException">Thrown when parameters are invalid.</exception>
    public static KeySet GeneratePgpKeySet(string mnemonicPhrase, string userId, PgpOptions? options = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(mnemonicPhrase);
        ArgumentException.ThrowIfNullOrWhiteSpace(userId);

        var (seed, creationTime) = DecodeMnemonic(mnemonicPhrase);
        options ??= PgpOptions.Default();

        try
        {
            return KeySet.Create(
                seed,
                UserId.FromString(userId),
                options.EncryptionIndex,
                options.SigningIndex,
                options.AuthenticationIndex);
        }
        finally
        {
            seed.Dispose();
        }
    }

    /// <summary>
    /// Generates a complete PGP key set from a seed and creation time.
    /// </summary>
    /// <param name="seed">The seed.</param>
    /// <param name="creationTime">The key creation time.</param>
    /// <param name="userId">The User ID for the key.</param>
    /// <param name="options">Optional PGP generation options.</param>
    /// <returns>A complete PGP key set.</returns>
    /// <exception cref="ArgumentNullException">Thrown when required parameters are null.</exception>
    public static KeySet GeneratePgpKeySet(Seed seed, DateTime creationTime, string userId, PgpOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(seed);
        ArgumentException.ThrowIfNullOrWhiteSpace(userId);

        options ??= PgpOptions.Default();

        // Update the seed's creation time if needed
        var seedWithTime = Seed.FromBytes(seed.ToBytes());
        
        try
        {
            return KeySet.Create(
                seedWithTime,
                UserId.FromString(userId),
                options.EncryptionIndex,
                options.SigningIndex,
                options.AuthenticationIndex);
        }
        finally
        {
            seedWithTime.Dispose();
        }
    }

    /// <summary>
    /// Exports a PGP key set as ASCII armored format.
    /// </summary>
    /// <param name="keySet">The key set to export.</param>
    /// <param name="options">Optional export options.</param>
    /// <returns>ASCII armored PGP key data.</returns>
    /// <exception cref="ArgumentNullException">Thrown when keySet is null.</exception>
    public static string ExportPgpArmored(KeySet keySet, PgpOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(keySet);
        
        options ??= PgpOptions.Default();

        if (options.IncludePrivateKeys)
        {
            return keySet.ExportPrivateKeyArmored(options.Password);
        }
        else
        {
            return keySet.ExportPublicKeyArmored();
        }
    }

    /// <summary>
    /// Exports a PGP key set as binary format.
    /// </summary>
    /// <param name="keySet">The key set to export.</param>
    /// <param name="options">Optional export options.</param>
    /// <returns>Binary PGP key data.</returns>
    /// <exception cref="ArgumentNullException">Thrown when keySet is null.</exception>
    public static byte[] ExportPgpBinary(KeySet keySet, PgpOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(keySet);
        
        options ??= PgpOptions.Default();

        if (options.IncludePrivateKeys)
        {
            return keySet.ExportPrivateKeyBinary(options.Password);
        }
        else
        {
            return keySet.ExportPublicKeyBinary();
        }
    }

    /// <summary>
    /// Creates a mnemonic phrase and corresponding PGP key set in one operation.
    /// This is a convenience method for generating new keys.
    /// </summary>
    /// <param name="userId">The User ID for the key.</param>
    /// <param name="options">Optional PGP generation options.</param>
    /// <returns>A tuple containing the mnemonic phrase and key set.</returns>
    /// <exception cref="ArgumentException">Thrown when userId is invalid.</exception>
    public static (string mnemonicPhrase, KeySet keySet) CreateNewPgpKey(string userId, PgpOptions? options = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userId);

        var seed = GenerateRandomSeed();
        var creationTime = DateTime.UtcNow;

        try
        {
            var mnemonicPhrase = EncodeMnemonic(seed, creationTime);
            var keySet = GeneratePgpKeySet(seed, creationTime, userId, options);

            return (mnemonicPhrase, keySet);
        }
        finally
        {
            seed.Dispose();
        }
    }

    /// <summary>
    /// Validates a mnemonic phrase.
    /// </summary>
    /// <param name="mnemonicPhrase">The mnemonic phrase to validate.</param>
    /// <returns>True if the mnemonic phrase is valid, false otherwise.</returns>
    public static bool IsValidMnemonic(string? mnemonicPhrase)
    {
        if (string.IsNullOrWhiteSpace(mnemonicPhrase))
            return false;

        try
        {
            DecodeMnemonic(mnemonicPhrase);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Gets information about a mnemonic phrase without fully decoding it.
    /// </summary>
    /// <param name="mnemonicPhrase">The mnemonic phrase.</param>
    /// <returns>Information about the mnemonic phrase.</returns>
    /// <exception cref="ArgumentException">Thrown when the mnemonic phrase is invalid.</exception>
    public static MnemonicInfo GetMnemonicInfo(string mnemonicPhrase)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(mnemonicPhrase);

        var words = mnemonicPhrase.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var (seed, creationTime) = DecodeMnemonic(mnemonicPhrase);

        try
        {
            return new MnemonicInfo
            {
                WordCount = words.Length,
                CreationTime = creationTime,
                IsEncrypted = MnemonicDecoder.DetectVersion(words).IsEncrypted,
                SeedHex = seed.ToHex(),
                Era = seed.Era
            };
        }
        finally
        {
            seed.Dispose();
        }
    }

    /// <summary>
    /// Information about a mnemonic phrase.
    /// </summary>
    public sealed class MnemonicInfo
    {
        /// <summary>
        /// Gets or sets the number of words in the mnemonic phrase.
        /// </summary>
        public int WordCount { get; set; }

        /// <summary>
        /// Gets or sets the creation time encoded in the mnemonic.
        /// </summary>
        public DateTime CreationTime { get; set; }

        /// <summary>
        /// Gets or sets whether the mnemonic phrase is encrypted.
        /// </summary>
        public bool IsEncrypted { get; set; }

        /// <summary>
        /// Gets or sets the seed as a hexadecimal string.
        /// </summary>
        public string SeedHex { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the era of the mnemonic.
        /// </summary>
        public Era Era { get; set; }

        /// <summary>
        /// Returns a string representation of the mnemonic info.
        /// </summary>
        /// <returns>A string representation.</returns>
        public override string ToString()
        {
            var type = IsEncrypted ? "encrypted" : "plaintext";
            return $"MnemonicInfo({WordCount} words, {type}, created {CreationTime:yyyy-MM-dd})";
        }
    }
}