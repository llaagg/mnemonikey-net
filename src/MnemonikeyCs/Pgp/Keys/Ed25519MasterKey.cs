using System;
using MnemonikeyCs.Core;
using MnemonikeyCs.Crypto;

namespace MnemonikeyCs.Pgp.Keys;

/// <summary>
/// Represents an Ed25519 master certification key generated from a seed using HKDF.
/// This key is used for certifying other keys and creating self-signatures.
/// </summary>
public sealed class Ed25519MasterKey : Ed25519KeyBase
{
    /// <summary>
    /// Initializes a new instance of the Ed25519MasterKey class.
    /// </summary>
    /// <param name="privateKeyBytes">The Ed25519 private key bytes.</param>
    /// <param name="creationTime">The key creation timestamp.</param>
    private Ed25519MasterKey(byte[] privateKeyBytes, DateTime creationTime)
        : base(privateKeyBytes, creationTime, KeyUsage.Certify | KeyUsage.Sign)
    {
    }

    /// <summary>
    /// Creates an Ed25519 master key from a seed and creation time.
    /// </summary>
    /// <param name="seed">The seed to derive the key from.</param>
    /// <param name="creationTime">The key creation timestamp.</param>
    /// <returns>A new Ed25519MasterKey instance.</returns>
    /// <exception cref="ArgumentNullException">Thrown when seed is null.</exception>
    public static Ed25519MasterKey FromSeed(Seed seed, DateTime creationTime)
    {
        ArgumentNullException.ThrowIfNull(seed);

        // First derive the root key using Argon2id
        var rootKey = Argon2Service.DeriveRootKey(seed, creationTime);
        
        try
        {
            // Then derive the master key using HKDF
            var masterKeyBytes = HkdfService.DeriveMasterKey(rootKey);
            
            try
            {
                return new Ed25519MasterKey(masterKeyBytes, creationTime);
            }
            finally
            {
                // Clear the derived key bytes
                masterKeyBytes.AsSpan().Clear();
            }
        }
        finally
        {
            // Clear the root key
            rootKey.AsSpan().Clear();
        }
    }

    /// <summary>
    /// Creates an Ed25519 master key directly from private key bytes.
    /// This is primarily used for testing or when the key material is already derived.
    /// </summary>
    /// <param name="privateKeyBytes">The Ed25519 private key bytes.</param>
    /// <param name="creationTime">The key creation timestamp.</param>
    /// <returns>A new Ed25519MasterKey instance.</returns>
    /// <exception cref="ArgumentNullException">Thrown when privateKeyBytes is null.</exception>
    /// <exception cref="ArgumentException">Thrown when privateKeyBytes is not 32 bytes.</exception>
    public static Ed25519MasterKey FromPrivateKey(byte[] privateKeyBytes, DateTime creationTime)
    {
        ArgumentNullException.ThrowIfNull(privateKeyBytes);
        
        if (privateKeyBytes.Length != Constants.Ed25519PrivateKeySize)
        {
            throw new ArgumentException($"Private key must be exactly {Constants.Ed25519PrivateKeySize} bytes", 
                nameof(privateKeyBytes));
        }

        return new Ed25519MasterKey(privateKeyBytes, creationTime);
    }

    /// <summary>
    /// Creates a self-certification signature for the master key with the specified user ID.
    /// </summary>
    /// <param name="userId">The user ID to certify.</param>
    /// <returns>The signature bytes.</returns>
    /// <exception cref="ArgumentNullException">Thrown when userId is null.</exception>
    public byte[] CreateSelfCertification(string userId)
    {
        ArgumentNullException.ThrowIfNull(userId);
        ThrowIfDisposed();

        // Create the data to sign for self-certification
        // This includes the public key packet data and user ID packet data
        var publicKeyData = SerializePublicKeyForSigning();
        var userIdData = System.Text.Encoding.UTF8.GetBytes(userId);

        // Combine the data according to OpenPGP specification
        var dataToSign = new byte[publicKeyData.Length + userIdData.Length];
        publicKeyData.CopyTo(dataToSign, 0);
        userIdData.CopyTo(dataToSign, publicKeyData.Length);

        return Sign(dataToSign);
    }

    /// <summary>
    /// Creates a subkey binding signature for the specified subkey.
    /// </summary>
    /// <param name="subkey">The subkey to bind.</param>
    /// <returns>The signature bytes.</returns>
    /// <exception cref="ArgumentNullException">Thrown when subkey is null.</exception>
    public byte[] CreateSubkeyBinding(IPgpKey subkey)
    {
        ArgumentNullException.ThrowIfNull(subkey);
        ThrowIfDisposed();

        // Create the data to sign for subkey binding
        // This includes the master key public key data and subkey public key data
        var masterKeyData = SerializePublicKeyForSigning();
        var subkeyData = SerializeSubkeyForSigning(subkey);

        // Combine the data according to OpenPGP specification
        var dataToSign = new byte[masterKeyData.Length + subkeyData.Length];
        masterKeyData.CopyTo(dataToSign, 0);
        subkeyData.CopyTo(dataToSign, masterKeyData.Length);

        return Sign(dataToSign);
    }

    /// <summary>
    /// Serializes the public key data for signature creation.
    /// </summary>
    /// <returns>The serialized public key data.</returns>
    private byte[] SerializePublicKeyForSigning()
    {
        // Create a minimal public key packet for signing
        // Format: version(1) + timestamp(4) + algorithm(1) + key_material_length(2) + algorithm(1) + public_key
        var timestamp = (uint)((DateTimeOffset)CreationTime).ToUnixTimeSeconds();
        var timestampBytes = BitConverter.GetBytes(timestamp);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(timestampBytes);

        var publicKeyBytes = PublicKeyBytes;
        var keyMaterialLength = (ushort)(1 + publicKeyBytes.Length);
        var keyMaterialLengthBytes = BitConverter.GetBytes(keyMaterialLength);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(keyMaterialLengthBytes);

        var result = new byte[1 + 4 + 1 + 2 + 1 + publicKeyBytes.Length];
        var offset = 0;

        result[offset++] = 4; // Version 4
        timestampBytes.CopyTo(result, offset);
        offset += 4;
        result[offset++] = (byte)Algorithm;
        keyMaterialLengthBytes.CopyTo(result, offset);
        offset += 2;
        result[offset++] = (byte)Algorithm; // Algorithm for key material
        publicKeyBytes.CopyTo(result, offset);

        return result;
    }

    /// <summary>
    /// Serializes the subkey data for signature creation.
    /// </summary>
    /// <param name="subkey">The subkey to serialize.</param>
    /// <returns>The serialized subkey data.</returns>
    private byte[] SerializeSubkeyForSigning(IPgpKey subkey)
    {
        // Create a minimal subkey packet for signing
        var timestamp = (uint)((DateTimeOffset)subkey.CreationTime).ToUnixTimeSeconds();
        var timestampBytes = BitConverter.GetBytes(timestamp);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(timestampBytes);

        var publicKeyBytes = subkey.PublicKeyBytes;
        var keyMaterialLength = (ushort)(1 + publicKeyBytes.Length);
        var keyMaterialLengthBytes = BitConverter.GetBytes(keyMaterialLength);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(keyMaterialLengthBytes);

        var result = new byte[1 + 4 + 1 + 2 + 1 + publicKeyBytes.Length];
        var offset = 0;

        result[offset++] = 4; // Version 4
        timestampBytes.CopyTo(result, offset);
        offset += 4;
        result[offset++] = (byte)subkey.Algorithm;
        keyMaterialLengthBytes.CopyTo(result, offset);
        offset += 2;
        result[offset++] = (byte)subkey.Algorithm; // Algorithm for key material
        publicKeyBytes.CopyTo(result, offset);

        return result;
    }
}