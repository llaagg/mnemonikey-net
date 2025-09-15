using System;
using System.Security.Cryptography;
using MnemonikeyCs.Core;

namespace MnemonikeyCs.Crypto;

/// <summary>
/// Provides HKDF (HMAC-based Key Derivation Function) services compatible with the Go implementation.
/// </summary>
public sealed class HkdfService
{
    /// <summary>
    /// Expands input key material using HKDF-Expand with SHA256.
    /// </summary>
    /// <param name="pseudoRandomKey">The input pseudo-random key (PRK).</param>
    /// <param name="length">The desired output length in bytes.</param>
    /// <param name="info">The optional info parameter for domain separation.</param>
    /// <returns>The expanded key material.</returns>
    /// <exception cref="ArgumentNullException">Thrown when pseudoRandomKey is null.</exception>
    /// <exception cref="ArgumentException">Thrown when parameters are invalid.</exception>
    public static byte[] Expand(byte[] pseudoRandomKey, int length, byte[]? info = null)
    {
        ArgumentNullException.ThrowIfNull(pseudoRandomKey);
        
        if (length <= 0)
            throw new ArgumentException("Length must be greater than 0", nameof(length));
        
        if (length > 255 * 32) // SHA256 hash length is 32 bytes, max 255 rounds
            throw new ArgumentException("Length exceeds maximum HKDF output length", nameof(length));

        info ??= Array.Empty<byte>();
        
        var output = new byte[length];
        var hash = new byte[32]; // SHA256 output size
        var counter = 1;
        var generatedBytes = 0;

        using var hmac = new HMACSHA256(pseudoRandomKey);
        
        while (generatedBytes < length)
        {
            // T(i) = HMAC-Hash(PRK, T(i-1) | info | i)
            if (counter > 1)
            {
                hmac.TransformBlock(hash, 0, hash.Length, null, 0);
            }
            
            if (info.Length > 0)
            {
                hmac.TransformBlock(info, 0, info.Length, null, 0);
            }
            
            var counterByte = new[] { (byte)counter };
            hmac.TransformFinalBlock(counterByte, 0, 1);
            
            hash = hmac.Hash!;
            
            var bytesToCopy = Math.Min(hash.Length, length - generatedBytes);
            Array.Copy(hash, 0, output, generatedBytes, bytesToCopy);
            
            generatedBytes += bytesToCopy;
            counter++;
            
            // Reset HMAC for next iteration
            hmac.Initialize();
        }
        
        return output;
    }

    /// <summary>
    /// Derives a master key from the root key.
    /// </summary>
    /// <param name="rootKey">The root key derived from Argon2id.</param>
    /// <returns>The 32-byte master key seed.</returns>
    public static byte[] DeriveMasterKey(byte[] rootKey)
    {
        var info = System.Text.Encoding.UTF8.GetBytes(Constants.KeyExpandInfoMaster);
        return Expand(rootKey, Constants.Ed25519PrivateKeySize, info);
    }

    /// <summary>
    /// Derives a subkey from the root key.
    /// </summary>
    /// <param name="rootKey">The root key derived from Argon2id.</param>
    /// <param name="subkeyType">The type of subkey to derive.</param>
    /// <param name="index">The subkey index for key cycling.</param>
    /// <returns>The 32-byte subkey seed.</returns>
    public static byte[] DeriveSubkey(byte[] rootKey, SubkeyType subkeyType, ushort index)
    {
        var info = BuildSubkeyInfo(subkeyType, index);
        var keySize = subkeyType == SubkeyType.Encryption 
            ? Constants.Curve25519PrivateKeySize 
            : Constants.Ed25519PrivateKeySize;
        
        return Expand(rootKey, keySize, info);
    }

    /// <summary>
    /// Builds the info parameter for subkey derivation.
    /// </summary>
    /// <param name="subkeyType">The subkey type.</param>
    /// <param name="index">The subkey index.</param>
    /// <returns>The info bytes for HKDF.</returns>
    private static byte[] BuildSubkeyInfo(SubkeyType subkeyType, ushort index)
    {
        var infoString = string.Format(Constants.KeyExpandInfoSubkeyFormat, subkeyType.ToInfoString());
        var infoBytes = System.Text.Encoding.UTF8.GetBytes(infoString);
        
        // Append the index as big-endian 16-bit integer
        var indexBytes = BitConverter.GetBytes(index);
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(indexBytes);
        }
        
        var result = new byte[infoBytes.Length + 2];
        infoBytes.CopyTo(result, 0);
        indexBytes.CopyTo(result, infoBytes.Length);
        
        return result;
    }

    /// <summary>
    /// Derives all keys for a complete key set from the root key.
    /// </summary>
    /// <param name="rootKey">The root key derived from Argon2id.</param>
    /// <param name="encryptionIndex">The encryption subkey index.</param>
    /// <param name="authenticationIndex">The authentication subkey index.</param>
    /// <param name="signingIndex">The signing subkey index.</param>
    /// <returns>A tuple containing all derived keys.</returns>
    public static (byte[] masterKey, byte[] encryptionKey, byte[] authenticationKey, byte[] signingKey) DeriveAllKeys(
        byte[] rootKey,
        ushort encryptionIndex = 0,
        ushort authenticationIndex = 0,
        ushort signingIndex = 0)
    {
        var masterKey = DeriveMasterKey(rootKey);
        var encryptionKey = DeriveSubkey(rootKey, SubkeyType.Encryption, encryptionIndex);
        var authenticationKey = DeriveSubkey(rootKey, SubkeyType.Authentication, authenticationIndex);
        var signingKey = DeriveSubkey(rootKey, SubkeyType.Signing, signingIndex);
        
        return (masterKey, encryptionKey, authenticationKey, signingKey);
    }
}