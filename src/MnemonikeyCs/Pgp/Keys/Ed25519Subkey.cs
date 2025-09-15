using System;
using MnemonikeyCs.Core;
using MnemonikeyCs.Crypto;

namespace MnemonikeyCs.Pgp.Keys;

/// <summary>
/// Represents an Ed25519 subkey for signing and authentication operations.
/// This key is derived from a seed using HKDF with configurable indices for key cycling.
/// </summary>
public sealed class Ed25519Subkey : Ed25519KeyBase
{
    /// <summary>
    /// Gets the subkey type.
    /// </summary>
    public SubkeyType SubkeyType { get; }

    /// <summary>
    /// Gets the subkey index used for key cycling.
    /// </summary>
    public ushort Index { get; }

    /// <summary>
    /// Initializes a new instance of the Ed25519Subkey class.
    /// </summary>
    /// <param name="privateKeyBytes">The Ed25519 private key bytes.</param>
    /// <param name="creationTime">The key creation timestamp.</param>
    /// <param name="subkeyType">The subkey type.</param>
    /// <param name="index">The subkey index.</param>
    private Ed25519Subkey(byte[] privateKeyBytes, DateTime creationTime, SubkeyType subkeyType, ushort index)
        : base(privateKeyBytes, creationTime, GetKeyUsageForSubkeyType(subkeyType))
    {
        SubkeyType = subkeyType;
        Index = index;
    }

    /// <summary>
    /// Creates an Ed25519 signing subkey from a seed and creation time.
    /// </summary>
    /// <param name="seed">The seed to derive the key from.</param>
    /// <param name="creationTime">The key creation timestamp.</param>
    /// <param name="index">The subkey index for key cycling (default: 0).</param>
    /// <returns>A new Ed25519Subkey instance for signing.</returns>
    /// <exception cref="ArgumentNullException">Thrown when seed is null.</exception>
    public static Ed25519Subkey CreateSigningKey(Seed seed, DateTime creationTime, ushort index = 0)
    {
        ArgumentNullException.ThrowIfNull(seed);

        // First derive the root key using Argon2id
        var rootKey = Argon2Service.DeriveRootKey(seed, creationTime);
        
        try
        {
            // Then derive the signing subkey using HKDF
            var subkeyBytes = HkdfService.DeriveSubkey(rootKey, SubkeyType.Signing, index);
            
            try
            {
                return new Ed25519Subkey(subkeyBytes, creationTime, SubkeyType.Signing, index);
            }
            finally
            {
                // Clear the derived key bytes
                subkeyBytes.AsSpan().Clear();
            }
        }
        finally
        {
            // Clear the root key
            rootKey.AsSpan().Clear();
        }
    }

    /// <summary>
    /// Creates an Ed25519 authentication subkey from a seed and creation time.
    /// </summary>
    /// <param name="seed">The seed to derive the key from.</param>
    /// <param name="creationTime">The key creation timestamp.</param>
    /// <param name="index">The subkey index for key cycling (default: 0).</param>
    /// <returns>A new Ed25519Subkey instance for authentication.</returns>
    /// <exception cref="ArgumentNullException">Thrown when seed is null.</exception>
    public static Ed25519Subkey CreateAuthenticationKey(Seed seed, DateTime creationTime, ushort index = 0)
    {
        ArgumentNullException.ThrowIfNull(seed);

        // First derive the root key using Argon2id
        var rootKey = Argon2Service.DeriveRootKey(seed, creationTime);
        
        try
        {
            // Then derive the authentication subkey using HKDF
            var subkeyBytes = HkdfService.DeriveSubkey(rootKey, SubkeyType.Authentication, index);
            
            try
            {
                return new Ed25519Subkey(subkeyBytes, creationTime, SubkeyType.Authentication, index);
            }
            finally
            {
                // Clear the derived key bytes
                subkeyBytes.AsSpan().Clear();
            }
        }
        finally
        {
            // Clear the root key
            rootKey.AsSpan().Clear();
        }
    }

    /// <summary>
    /// Creates an Ed25519 subkey directly from private key bytes.
    /// This is primarily used for testing or when the key material is already derived.
    /// </summary>
    /// <param name="privateKeyBytes">The Ed25519 private key bytes.</param>
    /// <param name="creationTime">The key creation timestamp.</param>
    /// <param name="subkeyType">The subkey type.</param>
    /// <param name="index">The subkey index.</param>
    /// <returns>A new Ed25519Subkey instance.</returns>
    /// <exception cref="ArgumentNullException">Thrown when privateKeyBytes is null.</exception>
    /// <exception cref="ArgumentException">Thrown when privateKeyBytes is not 32 bytes or subkeyType is invalid for Ed25519.</exception>
    public static Ed25519Subkey FromPrivateKey(byte[] privateKeyBytes, DateTime creationTime, SubkeyType subkeyType, ushort index = 0)
    {
        ArgumentNullException.ThrowIfNull(privateKeyBytes);
        
        if (privateKeyBytes.Length != Constants.Ed25519PrivateKeySize)
        {
            throw new ArgumentException($"Private key must be exactly {Constants.Ed25519PrivateKeySize} bytes", 
                nameof(privateKeyBytes));
        }

        if (subkeyType == SubkeyType.Encryption)
        {
            throw new ArgumentException("Ed25519 keys cannot be used for encryption. Use Curve25519Subkey instead.", 
                nameof(subkeyType));
        }

        return new Ed25519Subkey(privateKeyBytes, creationTime, subkeyType, index);
    }

    /// <summary>
    /// Gets the appropriate key usage flags for a subkey type.
    /// </summary>
    /// <param name="subkeyType">The subkey type.</param>
    /// <returns>The corresponding key usage flags.</returns>
    /// <exception cref="ArgumentException">Thrown when subkeyType is invalid for Ed25519.</exception>
    private static KeyUsage GetKeyUsageForSubkeyType(SubkeyType subkeyType)
    {
        return subkeyType switch
        {
            SubkeyType.Signing => KeyUsage.Sign,
            SubkeyType.Authentication => KeyUsage.Authenticate,
            SubkeyType.Encryption => throw new ArgumentException("Ed25519 keys cannot be used for encryption", nameof(subkeyType)),
            _ => throw new ArgumentOutOfRangeException(nameof(subkeyType), subkeyType, "Unknown subkey type")
        };
    }

    /// <summary>
    /// Returns a string representation of this subkey.
    /// </summary>
    /// <returns>A string representation including the subkey type and index.</returns>
    public override string ToString()
    {
        if (IsDisposed())
        {
            return $"Ed25519Subkey({SubkeyType}, index={Index}, disposed)";
        }
        
        var keyIdHex = Convert.ToHexString(KeyId).ToLowerInvariant();
        return $"Ed25519Subkey({SubkeyType}, index={Index}, keyId={keyIdHex[^8..]})";
    }
}