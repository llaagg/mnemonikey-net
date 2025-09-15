using System;
using Konscious.Security.Cryptography;
using MnemonikeyCs.Core;

namespace MnemonikeyCs.Crypto;

/// <summary>
/// Provides Argon2id key derivation services compatible with the Go implementation.
/// </summary>
public sealed class Argon2Service
{
    /// <summary>
    /// Derives a key using Argon2id with the same parameters as the Go implementation.
    /// </summary>
    /// <param name="password">The password bytes.</param>
    /// <param name="salt">The salt bytes.</param>
    /// <param name="iterations">The number of iterations (time parameter).</param>
    /// <param name="memorySize">The memory size in KB.</param>
    /// <param name="parallelism">The degree of parallelism.</param>
    /// <param name="keyLength">The desired key length in bytes.</param>
    /// <returns>The derived key bytes.</returns>
    /// <exception cref="ArgumentNullException">Thrown when password or salt is null.</exception>
    /// <exception cref="ArgumentException">Thrown when parameters are invalid.</exception>
    public static byte[] DeriveKey(
        byte[] password,
        byte[] salt,
        uint iterations,
        uint memorySize,
        uint parallelism,
        int keyLength)
    {
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(salt);
        
        if (iterations == 0)
            throw new ArgumentException("Iterations must be greater than 0", nameof(iterations));
        
        if (memorySize == 0)
            throw new ArgumentException("Memory size must be greater than 0", nameof(memorySize));
        
        if (parallelism == 0)
            throw new ArgumentException("Parallelism must be greater than 0", nameof(parallelism));
        
        if (keyLength <= 0)
            throw new ArgumentException("Key length must be greater than 0", nameof(keyLength));

        // Handle empty passwords by using a single zero byte (compatible with Go)
        var passwordBytes = password.Length == 0 ? new byte[] { 0 } : password;
        
        using var argon2 = new Argon2id(passwordBytes)
        {
            Salt = salt,
            Iterations = (int)iterations,
            MemorySize = (int)memorySize,
            DegreeOfParallelism = (int)parallelism
        };

        return argon2.GetBytes(keyLength);
    }

    /// <summary>
    /// Derives a key using the standard mnemonikey Argon2id parameters.
    /// </summary>
    /// <param name="password">The password bytes.</param>
    /// <param name="salt">The salt bytes.</param>
    /// <param name="keyLength">The desired key length in bytes.</param>
    /// <returns>The derived key bytes.</returns>
    public static byte[] DeriveKeyStandard(byte[] password, byte[] salt, int keyLength)
    {
        return DeriveKey(
            password,
            salt,
            Constants.ArgonTimeFactor,
            Constants.ArgonMemoryFactor,
            Constants.ArgonThreads,
            keyLength);
    }

    /// <summary>
    /// Derives the root key from a seed and creation timestamp.
    /// This is the primary key derivation used in mnemonikey.
    /// </summary>
    /// <param name="seed">The 128-bit seed.</param>
    /// <param name="creationTime">The key creation timestamp.</param>
    /// <returns>The 32-byte root key.</returns>
    public static byte[] DeriveRootKey(Seed seed, DateTime creationTime)
    {
        ArgumentNullException.ThrowIfNull(seed);
        
        var passwordBytes = seed.ToBytes();
        var saltBytes = BitConverter.GetBytes((uint)((DateTimeOffset)creationTime).ToUnixTimeSeconds());
        
        // Convert to big-endian if necessary
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(saltBytes);
        }
        
        try
        {
            return DeriveKeyStandard(passwordBytes, saltBytes, Constants.RootKeySize);
        }
        finally
        {
            // Clear sensitive data
            Array.Clear(passwordBytes);
        }
    }

    /// <summary>
    /// Derives an encryption key for encrypted mnemonic phrases.
    /// </summary>
    /// <param name="password">The user password.</param>
    /// <param name="salt">The salt value.</param>
    /// <param name="creationOffset">The creation offset.</param>
    /// <returns>The encryption key and verification bytes.</returns>
    public static byte[] DeriveEncryptionKey(byte[] password, uint salt, uint creationOffset)
    {
        ArgumentNullException.ThrowIfNull(password);
        
        // Combine salt and creation offset as in Go implementation
        // salt (19 bits) || creationOffset (31 bits) = 50 bits total = 7 bytes (6.25 bytes rounded up)
        var combinedSalt = new byte[7];
        
        // Pack the 50-bit value: salt || creationOffset
        var combined = ((ulong)salt << 31) | creationOffset;
        
        // Convert to big-endian bytes
        for (int i = 6; i >= 0; i--)
        {
            combinedSalt[6 - i] = (byte)(combined >> (i * 8));
        }
        
        // Derive 17 bytes: 16 for AES key + 1 for verification
        return DeriveKeyStandard(password, combinedSalt, 17);
    }

    /// <summary>
    /// Derives an encryption key for encrypted mnemonic phrases using combined salt.
    /// </summary>
    /// <param name="password">The user password.</param>
    /// <param name="combinedSalt">The pre-combined salt bytes.</param>
    /// <returns>The encryption key (17 bytes: 16 for AES + 1 for verification).</returns>
    public static byte[] DeriveKeyForEncryption(ReadOnlySpan<byte> password, byte[] combinedSalt)
    {
        return DeriveKeyStandard(password.ToArray(), combinedSalt, 17);
    }
}