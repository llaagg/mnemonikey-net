using System;
using NSec.Cryptography;

namespace MnemonikeyCs.Crypto;

/// <summary>
/// Provides Ed25519 cryptographic operations compatible with the Go implementation.
/// </summary>
public sealed class Ed25519Service
{
    private static readonly SignatureAlgorithm Ed25519Algorithm = SignatureAlgorithm.Ed25519;

    /// <summary>
    /// Represents an Ed25519 key pair.
    /// </summary>
    public readonly struct Ed25519KeyPair : IDisposable
    {
        /// <summary>
        /// The private key.
        /// </summary>
        public Key PrivateKey { get; init; }
        
        /// <summary>
        /// The public key.
        /// </summary>
        public PublicKey PublicKey { get; init; }

        /// <summary>
        /// Gets the private key bytes (32 bytes).
        /// </summary>
        public byte[] PrivateKeyBytes => PrivateKey.Export(KeyBlobFormat.RawPrivateKey);
        
        /// <summary>
        /// Gets the public key bytes (32 bytes).
        /// </summary>
        public byte[] PublicKeyBytes => PublicKey.Export(KeyBlobFormat.RawPublicKey);

        /// <summary>
        /// Disposes of the key pair, securely clearing sensitive data.
        /// </summary>
        public void Dispose()
        {
            PrivateKey?.Dispose();
        }
    }

    /// <summary>
    /// Generates an Ed25519 key pair from a 32-byte seed.
    /// </summary>
    /// <param name="seed">The 32-byte seed for key generation.</param>
    /// <returns>An Ed25519 key pair.</returns>
    /// <exception cref="ArgumentNullException">Thrown when seed is null.</exception>
    /// <exception cref="ArgumentException">Thrown when seed is not 32 bytes.</exception>
    public static Ed25519KeyPair GenerateKeyPair(byte[] seed)
    {
        ArgumentNullException.ThrowIfNull(seed);
        
        if (seed.Length != 32)
            throw new ArgumentException("Seed must be exactly 32 bytes", nameof(seed));

        var creationParameters = new KeyCreationParameters
        {
            ExportPolicy = KeyExportPolicies.AllowPlaintextExport
        };

        var privateKey = Key.Import(Ed25519Algorithm, seed, KeyBlobFormat.RawPrivateKey, creationParameters);
        var publicKey = privateKey.PublicKey;

        return new Ed25519KeyPair
        {
            PrivateKey = privateKey,
            PublicKey = publicKey
        };
    }

    /// <summary>
    /// Creates an Ed25519 private key from raw bytes.
    /// </summary>
    /// <param name="privateKeyBytes">The 32-byte private key.</param>
    /// <returns>An Ed25519 private key.</returns>
    /// <exception cref="ArgumentNullException">Thrown when privateKeyBytes is null.</exception>
    /// <exception cref="ArgumentException">Thrown when privateKeyBytes is not 32 bytes.</exception>
    public static Key ImportPrivateKey(byte[] privateKeyBytes)
    {
        ArgumentNullException.ThrowIfNull(privateKeyBytes);
        
        if (privateKeyBytes.Length != 32)
            throw new ArgumentException("Private key must be exactly 32 bytes", nameof(privateKeyBytes));

        var creationParameters = new KeyCreationParameters
        {
            ExportPolicy = KeyExportPolicies.AllowPlaintextExport
        };

        return Key.Import(Ed25519Algorithm, privateKeyBytes, KeyBlobFormat.RawPrivateKey, creationParameters);
    }

    /// <summary>
    /// Creates an Ed25519 public key from raw bytes.
    /// </summary>
    /// <param name="publicKeyBytes">The 32-byte public key.</param>
    /// <returns>An Ed25519 public key.</returns>
    /// <exception cref="ArgumentNullException">Thrown when publicKeyBytes is null.</exception>
    /// <exception cref="ArgumentException">Thrown when publicKeyBytes is not 32 bytes.</exception>
    public static PublicKey ImportPublicKey(byte[] publicKeyBytes)
    {
        ArgumentNullException.ThrowIfNull(publicKeyBytes);
        
        if (publicKeyBytes.Length != 32)
            throw new ArgumentException("Public key must be exactly 32 bytes", nameof(publicKeyBytes));

        return PublicKey.Import(Ed25519Algorithm, publicKeyBytes, KeyBlobFormat.RawPublicKey);
    }

    /// <summary>
    /// Signs a message with an Ed25519 private key.
    /// </summary>
    /// <param name="privateKey">The Ed25519 private key.</param>
    /// <param name="message">The message to sign.</param>
    /// <returns>The 64-byte signature.</returns>
    /// <exception cref="ArgumentNullException">Thrown when privateKey or message is null.</exception>
    public static byte[] Sign(Key privateKey, byte[] message)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        ArgumentNullException.ThrowIfNull(message);
        
        if (privateKey.Algorithm != Ed25519Algorithm)
            throw new ArgumentException("Key must be an Ed25519 key", nameof(privateKey));

        return Ed25519Algorithm.Sign(privateKey, message);
    }

    /// <summary>
    /// Signs a message with Ed25519 private key bytes.
    /// </summary>
    /// <param name="privateKeyBytes">The 32-byte private key.</param>
    /// <param name="message">The message to sign.</param>
    /// <returns>The 64-byte signature.</returns>
    public static byte[] Sign(byte[] privateKeyBytes, byte[] message)
    {
        using var privateKey = ImportPrivateKey(privateKeyBytes);
        return Sign(privateKey, message);
    }

    /// <summary>
    /// Verifies an Ed25519 signature.
    /// </summary>
    /// <param name="publicKey">The Ed25519 public key.</param>
    /// <param name="message">The original message.</param>
    /// <param name="signature">The signature to verify.</param>
    /// <returns>true if the signature is valid; otherwise, false.</returns>
    /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
    public static bool Verify(PublicKey publicKey, byte[] message, byte[] signature)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(signature);
        
        if (publicKey.Algorithm != Ed25519Algorithm)
            throw new ArgumentException("Key must be an Ed25519 key", nameof(publicKey));

        return Ed25519Algorithm.Verify(publicKey, message, signature);
    }

    /// <summary>
    /// Verifies an Ed25519 signature using public key bytes.
    /// </summary>
    /// <param name="publicKeyBytes">The 32-byte public key.</param>
    /// <param name="message">The original message.</param>
    /// <param name="signature">The signature to verify.</param>
    /// <returns>true if the signature is valid; otherwise, false.</returns>
    public static bool Verify(byte[] publicKeyBytes, byte[] message, byte[] signature)
    {
        var publicKey = ImportPublicKey(publicKeyBytes);
        return Verify(publicKey, message, signature);
    }

    /// <summary>
    /// Derives the public key from an Ed25519 private key.
    /// </summary>
    /// <param name="privateKeyBytes">The 32-byte private key.</param>
    /// <returns>The 32-byte public key.</returns>
    public static byte[] DerivePublicKey(byte[] privateKeyBytes)
    {
        using var keyPair = GenerateKeyPair(privateKeyBytes);
        return keyPair.PublicKeyBytes;
    }

    /// <summary>
    /// Computes the fingerprint (SHA256 hash) of an Ed25519 public key.
    /// This is used for PGP key identification.
    /// </summary>
    /// <param name="publicKeyBytes">The 32-byte public key.</param>
    /// <param name="creationTime">The key creation timestamp.</param>
    /// <param name="algorithm">The algorithm identifier (22 for Ed25519).</param>
    /// <returns>The 32-byte fingerprint.</returns>
    public static byte[] ComputeFingerprint(byte[] publicKeyBytes, DateTime creationTime, byte algorithm = 22)
    {
        ArgumentNullException.ThrowIfNull(publicKeyBytes);
        
        if (publicKeyBytes.Length != 32)
            throw new ArgumentException("Public key must be exactly 32 bytes", nameof(publicKeyBytes));

        // Create the data to hash according to RFC 4880 Section 12.2
        var timestamp = (uint)((DateTimeOffset)creationTime).ToUnixTimeSeconds();
        var timestampBytes = BitConverter.GetBytes(timestamp);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(timestampBytes);

        // Build the fingerprint input: version (1 byte) + timestamp (4 bytes) + algorithm (1 byte) + key material length (2 bytes) + key material
        var keyMaterialLength = (ushort)(1 + publicKeyBytes.Length); // Algorithm byte + key bytes
        var keyMaterialLengthBytes = BitConverter.GetBytes(keyMaterialLength);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(keyMaterialLengthBytes);

        var fingerprintInput = new byte[1 + 4 + 1 + 2 + 1 + publicKeyBytes.Length];
        var offset = 0;
        
        fingerprintInput[offset++] = 4; // Version 4
        timestampBytes.CopyTo(fingerprintInput, offset);
        offset += 4;
        fingerprintInput[offset++] = algorithm;
        keyMaterialLengthBytes.CopyTo(fingerprintInput, offset);
        offset += 2;
        fingerprintInput[offset++] = algorithm; // Algorithm again for key material
        publicKeyBytes.CopyTo(fingerprintInput, offset);

        using var sha256 = System.Security.Cryptography.SHA256.Create();
        return sha256.ComputeHash(fingerprintInput);
    }
}