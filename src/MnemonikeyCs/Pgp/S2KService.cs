using System;
using System.Security.Cryptography;
using MnemonikeyCs.Pgp.Packets;
using PgpHashAlgorithm = MnemonikeyCs.Pgp.Packets.HashAlgorithm;
using PgpSymmetricAlgorithm = MnemonikeyCs.Pgp.Packets.SymmetricAlgorithm;
using SystemHashAlgorithm = System.Security.Cryptography.HashAlgorithm;
using SystemSymmetricAlgorithm = System.Security.Cryptography.SymmetricAlgorithm;

namespace MnemonikeyCs.Pgp;

/// <summary>
/// Provides String-to-Key (S2K) password encryption services for PGP keys.
/// </summary>
public static class S2KService
{
    /// <summary>
    /// Default iteration count for iterated and salted S2K (65536 iterations).
    /// </summary>
    public const uint DefaultIterationCount = 65536;

    /// <summary>
    /// Default salt size in bytes.
    /// </summary>
    public const int DefaultSaltSize = 8;

    /// <summary>
    /// Represents S2K (String-to-Key) parameters for password-based encryption.
    /// </summary>
    public sealed class S2KParameters
    {
        /// <summary>
        /// Gets the S2K type.
        /// </summary>
        public S2KType Type { get; init; }

        /// <summary>
        /// Gets the hash algorithm used for key derivation.
        /// </summary>
        public PgpHashAlgorithm HashAlgorithm { get; init; } = PgpHashAlgorithm.SHA256;

        /// <summary>
        /// Gets the salt bytes (null for simple S2K).
        /// </summary>
        public byte[]? Salt { get; init; }

        /// <summary>
        /// Gets the iteration count (only used for iterated and salted S2K).
        /// </summary>
        public uint IterationCount { get; init; } = DefaultIterationCount;

        /// <summary>
        /// Gets the symmetric algorithm used for encryption.
        /// </summary>
        public PgpSymmetricAlgorithm SymmetricAlgorithm { get; init; } = PgpSymmetricAlgorithm.AES256;
    }

    /// <summary>
    /// Creates default S2K parameters for iterated and salted S2K with secure defaults.
    /// </summary>
    /// <param name="salt">Optional salt (generates random salt if null).</param>
    /// <returns>S2K parameters with secure defaults.</returns>
    public static S2KParameters CreateDefaultParameters(byte[]? salt = null)
    {
        salt ??= GenerateRandomSalt();

        return new S2KParameters
        {
            Type = S2KType.IteratedAndSalted,
            HashAlgorithm = PgpHashAlgorithm.SHA256,
            Salt = salt,
            IterationCount = DefaultIterationCount,
            SymmetricAlgorithm = PgpSymmetricAlgorithm.AES256
        };
    }

    /// <summary>
    /// Generates a random salt for S2K.
    /// </summary>
    /// <param name="saltSize">The size of the salt in bytes.</param>
    /// <returns>A random salt.</returns>
    public static byte[] GenerateRandomSalt(int saltSize = DefaultSaltSize)
    {
        if (saltSize <= 0)
            throw new ArgumentException("Salt size must be positive", nameof(saltSize));

        var salt = new byte[saltSize];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(salt);
        return salt;
    }

    /// <summary>
    /// Derives a key from a password using the specified S2K parameters.
    /// </summary>
    /// <param name="password">The password string.</param>
    /// <param name="parameters">The S2K parameters.</param>
    /// <param name="keySize">The desired key size in bytes.</param>
    /// <returns>The derived key.</returns>
    /// <exception cref="ArgumentNullException">Thrown when password or parameters is null.</exception>
    /// <exception cref="ArgumentException">Thrown when parameters are invalid.</exception>
    public static byte[] DeriveKey(string password, S2KParameters parameters, int keySize)
    {
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(parameters);

        if (keySize <= 0)
            throw new ArgumentException("Key size must be positive", nameof(keySize));

        var passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);

        try
        {
            return parameters.Type switch
            {
                S2KType.Simple => DeriveSimpleS2K(passwordBytes, parameters.HashAlgorithm, keySize),
                S2KType.Salted => DeriveSaltedS2K(passwordBytes, parameters.Salt!, parameters.HashAlgorithm, keySize),
                S2KType.IteratedAndSalted => DeriveIteratedSaltedS2K(passwordBytes, parameters.Salt!, parameters.HashAlgorithm, parameters.IterationCount, keySize),
                _ => throw new ArgumentException($"Unsupported S2K type: {parameters.Type}")
            };
        }
        finally
        {
            // Clear password bytes from memory
            passwordBytes.AsSpan().Clear();
        }
    }

    /// <summary>
    /// Encrypts key material using password-based encryption.
    /// </summary>
    /// <param name="keyMaterial">The key material to encrypt.</param>
    /// <param name="password">The password.</param>
    /// <param name="parameters">The S2K parameters (uses defaults if null).</param>
    /// <returns>A tuple containing the encrypted data and S2K parameters used.</returns>
    public static (byte[] encryptedData, S2KParameters parameters) EncryptKeyMaterial(
        byte[] keyMaterial, 
        string password, 
        S2KParameters? parameters = null)
    {
        ArgumentNullException.ThrowIfNull(keyMaterial);
        ArgumentNullException.ThrowIfNull(password);

        parameters ??= CreateDefaultParameters();
        
        var keySize = GetKeySize(parameters.SymmetricAlgorithm);
        var derivedKey = DeriveKey(password, parameters, keySize);

        try
        {
            var encryptedData = EncryptWithSymmetricAlgorithm(keyMaterial, derivedKey, parameters.SymmetricAlgorithm);
            return (encryptedData, parameters);
        }
        finally
        {
            // Clear derived key from memory
            derivedKey.AsSpan().Clear();
        }
    }

    /// <summary>
    /// Decrypts key material using password-based encryption.
    /// </summary>
    /// <param name="encryptedData">The encrypted data.</param>
    /// <param name="password">The password.</param>
    /// <param name="parameters">The S2K parameters.</param>
    /// <returns>The decrypted key material.</returns>
    public static byte[] DecryptKeyMaterial(byte[] encryptedData, string password, S2KParameters parameters)
    {
        ArgumentNullException.ThrowIfNull(encryptedData);
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(parameters);

        var keySize = GetKeySize(parameters.SymmetricAlgorithm);
        var derivedKey = DeriveKey(password, parameters, keySize);

        try
        {
            return DecryptWithSymmetricAlgorithm(encryptedData, derivedKey, parameters.SymmetricAlgorithm);
        }
        finally
        {
            // Clear derived key from memory
            derivedKey.AsSpan().Clear();
        }
    }

    /// <summary>
    /// Encodes the iteration count as a single byte according to RFC 4880.
    /// </summary>
    /// <param name="iterationCount">The iteration count.</param>
    /// <returns>The encoded byte.</returns>
    public static byte EncodeIterationCount(uint iterationCount)
    {
        if (iterationCount < 1024)
            return 0;

        // Find the closest encoded value
        var log2 = Math.Log2(iterationCount);
        var encodedValue = (int)Math.Round((log2 - 6) * 16);
        
        return (byte)Math.Max(0, Math.Min(255, encodedValue));
    }

    /// <summary>
    /// Decodes the iteration count from a single byte according to RFC 4880.
    /// </summary>
    /// <param name="encodedValue">The encoded byte value.</param>
    /// <returns>The iteration count.</returns>
    public static uint DecodeIterationCount(byte encodedValue)
    {
        return (uint)(16 + (encodedValue & 15)) << ((encodedValue >> 4) + 6);
    }

    /// <summary>
    /// Derives a key using Simple S2K.
    /// </summary>
    /// <param name="password">The password bytes.</param>
    /// <param name="hashAlgorithm">The hash algorithm.</param>
    /// <param name="keySize">The desired key size.</param>
    /// <returns>The derived key.</returns>
    private static byte[] DeriveSimpleS2K(byte[] password, PgpHashAlgorithm hashAlgorithm, int keySize)
    {
        return HashRepeatedly(password, hashAlgorithm, keySize);
    }

    /// <summary>
    /// Derives a key using Salted S2K.
    /// </summary>
    /// <param name="password">The password bytes.</param>
    /// <param name="salt">The salt bytes.</param>
    /// <param name="hashAlgorithm">The hash algorithm.</param>
    /// <param name="keySize">The desired key size.</param>
    /// <returns>The derived key.</returns>
    private static byte[] DeriveSaltedS2K(byte[] password, byte[] salt, PgpHashAlgorithm hashAlgorithm, int keySize)
    {
        ArgumentNullException.ThrowIfNull(salt);

        var saltedPassword = new byte[salt.Length + password.Length];
        salt.CopyTo(saltedPassword, 0);
        password.CopyTo(saltedPassword, salt.Length);

        try
        {
            return HashRepeatedly(saltedPassword, hashAlgorithm, keySize);
        }
        finally
        {
            saltedPassword.AsSpan().Clear();
        }
    }

    /// <summary>
    /// Derives a key using Iterated and Salted S2K.
    /// </summary>
    /// <param name="password">The password bytes.</param>
    /// <param name="salt">The salt bytes.</param>
    /// <param name="hashAlgorithm">The hash algorithm.</param>
    /// <param name="iterationCount">The iteration count.</param>
    /// <param name="keySize">The desired key size.</param>
    /// <returns>The derived key.</returns>
    private static byte[] DeriveIteratedSaltedS2K(byte[] password, byte[] salt, PgpHashAlgorithm hashAlgorithm, uint iterationCount, int keySize)
    {
        ArgumentNullException.ThrowIfNull(salt);

        var saltedPassword = new byte[salt.Length + password.Length];
        salt.CopyTo(saltedPassword, 0);
        password.CopyTo(saltedPassword, salt.Length);

        try
        {
            return HashWithIteration(saltedPassword, hashAlgorithm, iterationCount, keySize);
        }
        finally
        {
            saltedPassword.AsSpan().Clear();
        }
    }

    /// <summary>
    /// Hashes data repeatedly to produce the desired key length.
    /// </summary>
    /// <param name="data">The data to hash.</param>
    /// <param name="hashAlgorithm">The hash algorithm.</param>
    /// <param name="keySize">The desired key size.</param>
    /// <returns>The hash-derived key.</returns>
    private static byte[] HashRepeatedly(byte[] data, PgpHashAlgorithm hashAlgorithm, int keySize)
    {
        var result = new byte[keySize];
        var hashSize = GetHashSize(hashAlgorithm);
        var rounds = (keySize + hashSize - 1) / hashSize;

        for (int round = 0; round < rounds; round++)
        {
            using var hash = CreateHashAlgorithm(hashAlgorithm);
            
            // Add preload bytes for subsequent rounds
            for (int i = 0; i < round; i++)
            {
                hash.TransformBlock(new byte[] { 0 }, 0, 1, null, 0);
            }

            hash.TransformFinalBlock(data, 0, data.Length);
            var hashResult = hash.Hash!;

            var bytesToCopy = Math.Min(hashResult.Length, keySize - round * hashSize);
            Array.Copy(hashResult, 0, result, round * hashSize, bytesToCopy);
        }

        return result;
    }

    /// <summary>
    /// Hashes data with iteration to produce the desired key length.
    /// </summary>
    /// <param name="data">The data to hash.</param>
    /// <param name="hashAlgorithm">The hash algorithm.</param>
    /// <param name="iterationCount">The iteration count.</param>
    /// <param name="keySize">The desired key size.</param>
    /// <returns>The hash-derived key.</returns>
    private static byte[] HashWithIteration(byte[] data, PgpHashAlgorithm hashAlgorithm, uint iterationCount, int keySize)
    {
        var result = new byte[keySize];
        var hashSize = GetHashSize(hashAlgorithm);
        var rounds = (keySize + hashSize - 1) / hashSize;

        for (int round = 0; round < rounds; round++)
        {
            using var hash = CreateHashAlgorithm(hashAlgorithm);
            
            // Add preload bytes for subsequent rounds
            for (int i = 0; i < round; i++)
            {
                hash.TransformBlock(new byte[] { 0 }, 0, 1, null, 0);
            }

            var totalBytes = Math.Max(iterationCount, (uint)data.Length);
            var fullCycles = totalBytes / (uint)data.Length;
            var remainingBytes = totalBytes % (uint)data.Length;

            // Hash full cycles of data
            for (uint cycle = 0; cycle < fullCycles; cycle++)
            {
                hash.TransformBlock(data, 0, data.Length, null, 0);
            }

            // Hash remaining partial data
            if (remainingBytes > 0)
            {
                hash.TransformFinalBlock(data, 0, (int)remainingBytes);
            }
            else
            {
                hash.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
            }

            var hashResult = hash.Hash!;
            var bytesToCopy = Math.Min(hashResult.Length, keySize - round * hashSize);
            Array.Copy(hashResult, 0, result, round * hashSize, bytesToCopy);
        }

        return result;
    }

    /// <summary>
    /// Gets the hash size for a hash algorithm.
    /// </summary>
    /// <param name="hashAlgorithm">The hash algorithm.</param>
    /// <returns>The hash size in bytes.</returns>
    private static int GetHashSize(PgpHashAlgorithm hashAlgorithm)
    {
        return hashAlgorithm switch
        {
            PgpHashAlgorithm.SHA256 => 32,
            PgpHashAlgorithm.SHA384 => 48,
            PgpHashAlgorithm.SHA512 => 64,
            PgpHashAlgorithm.SHA224 => 28,
            PgpHashAlgorithm.SHA1 => 20,
            _ => throw new NotSupportedException($"Hash algorithm {hashAlgorithm} is not supported")
        };
    }

    /// <summary>
    /// Gets the key size for a symmetric algorithm.
    /// </summary>
    /// <param name="algorithm">The symmetric algorithm.</param>
    /// <returns>The key size in bytes.</returns>
    private static int GetKeySize(PgpSymmetricAlgorithm algorithm)
    {
        return algorithm switch
        {
            PgpSymmetricAlgorithm.AES128 => 16,
            PgpSymmetricAlgorithm.AES192 => 24,
            PgpSymmetricAlgorithm.AES256 => 32,
            PgpSymmetricAlgorithm.TripleDES => 24,
            PgpSymmetricAlgorithm.CAST5 => 16,
            PgpSymmetricAlgorithm.Blowfish => 16,
            _ => throw new NotSupportedException($"Symmetric algorithm {algorithm} is not supported")
        };
    }

    /// <summary>
    /// Creates a hash algorithm instance.
    /// </summary>
    /// <param name="hashAlgorithm">The hash algorithm type.</param>
    /// <returns>A hash algorithm instance.</returns>
    private static SystemHashAlgorithm CreateHashAlgorithm(PgpHashAlgorithm hashAlgorithm)
    {
        return hashAlgorithm switch
        {
            PgpHashAlgorithm.SHA256 => SHA256.Create(),
            PgpHashAlgorithm.SHA384 => SHA384.Create(),
            PgpHashAlgorithm.SHA512 => SHA512.Create(),
            PgpHashAlgorithm.SHA224 => throw new NotSupportedException("SHA224 is not supported by .NET"),
            PgpHashAlgorithm.SHA1 => SHA1.Create(),
            _ => throw new NotSupportedException($"Hash algorithm {hashAlgorithm} is not supported")
        };
    }

    /// <summary>
    /// Encrypts data with a symmetric algorithm.
    /// </summary>
    /// <param name="data">The data to encrypt.</param>
    /// <param name="key">The encryption key.</param>
    /// <param name="algorithm">The symmetric algorithm.</param>
    /// <returns>The encrypted data.</returns>
    private static byte[] EncryptWithSymmetricAlgorithm(byte[] data, byte[] key, PgpSymmetricAlgorithm algorithm)
    {
        return algorithm switch
        {
            PgpSymmetricAlgorithm.AES128 or PgpSymmetricAlgorithm.AES192 or PgpSymmetricAlgorithm.AES256 => EncryptWithAes(data, key),
            _ => throw new NotSupportedException($"Symmetric algorithm {algorithm} encryption is not yet implemented")
        };
    }

    /// <summary>
    /// Decrypts data with a symmetric algorithm.
    /// </summary>
    /// <param name="encryptedData">The encrypted data.</param>
    /// <param name="key">The decryption key.</param>
    /// <param name="algorithm">The symmetric algorithm.</param>
    /// <returns>The decrypted data.</returns>
    private static byte[] DecryptWithSymmetricAlgorithm(byte[] encryptedData, byte[] key, PgpSymmetricAlgorithm algorithm)
    {
        return algorithm switch
        {
            PgpSymmetricAlgorithm.AES128 or PgpSymmetricAlgorithm.AES192 or PgpSymmetricAlgorithm.AES256 => DecryptWithAes(encryptedData, key),
            _ => throw new NotSupportedException($"Symmetric algorithm {algorithm} decryption is not yet implemented")
        };
    }

    /// <summary>
    /// Encrypts data with AES in CFB mode (as used in OpenPGP).
    /// </summary>
    /// <param name="data">The data to encrypt.</param>
    /// <param name="key">The AES key.</param>
    /// <returns>The encrypted data.</returns>
    private static byte[] EncryptWithAes(byte[] data, byte[] key)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.Mode = CipherMode.CFB;
        aes.Padding = PaddingMode.None;
        
        // Generate random IV
        aes.GenerateIV();
        
        using var encryptor = aes.CreateEncryptor();
        var encryptedData = encryptor.TransformFinalBlock(data, 0, data.Length);
        
        // Prepend IV to encrypted data
        var result = new byte[aes.IV.Length + encryptedData.Length];
        aes.IV.CopyTo(result, 0);
        encryptedData.CopyTo(result, aes.IV.Length);
        
        return result;
    }

    /// <summary>
    /// Decrypts AES-encrypted data in CFB mode.
    /// </summary>
    /// <param name="encryptedData">The encrypted data with IV prepended.</param>
    /// <param name="key">The AES key.</param>
    /// <returns>The decrypted data.</returns>
    private static byte[] DecryptWithAes(byte[] encryptedData, byte[] key)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.Mode = CipherMode.CFB;
        aes.Padding = PaddingMode.None;
        
        // Extract IV from the beginning of encrypted data
        var ivSize = aes.BlockSize / 8;
        if (encryptedData.Length < ivSize)
            throw new ArgumentException("Encrypted data is too short to contain IV");
        
        var iv = new byte[ivSize];
        Array.Copy(encryptedData, 0, iv, 0, ivSize);
        aes.IV = iv;
        
        // Decrypt the remaining data
        using var decryptor = aes.CreateDecryptor();
        return decryptor.TransformFinalBlock(encryptedData, ivSize, encryptedData.Length - ivSize);
    }
}