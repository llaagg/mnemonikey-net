using System;
using System.Security.Cryptography;
using MnemonikeyCs.Core;
using MnemonikeyCs.Crypto;
using NSec.Cryptography;

namespace MnemonikeyCs.Pgp.Keys;

/// <summary>
/// Represents a Curve25519 subkey for encryption operations.
/// This key is derived from a seed using HKDF and converted from Ed25519 to Curve25519.
/// </summary>
public sealed class Curve25519Subkey : BaseKey
{
    private readonly byte[] _privateKeyBytes;
    private readonly byte[] _publicKeyBytes;
    private readonly Key _nsecKey;

    /// <summary>
    /// Gets the subkey index used for key cycling.
    /// </summary>
    public ushort Index { get; }

    /// <summary>
    /// Initializes a new instance of the Curve25519Subkey class.
    /// </summary>
    /// <param name="privateKeyBytes">The Curve25519 private key bytes.</param>
    /// <param name="creationTime">The key creation timestamp.</param>
    /// <param name="index">The subkey index.</param>
    private Curve25519Subkey(byte[] privateKeyBytes, DateTime creationTime, ushort index)
        : base(creationTime, PgpAlgorithm.Curve25519, KeyUsage.EncryptCommunications | KeyUsage.EncryptStorage)
    {
        ArgumentNullException.ThrowIfNull(privateKeyBytes);
        
        if (privateKeyBytes.Length != Constants.Curve25519PrivateKeySize)
            throw new ArgumentException($"Curve25519 private key must be {Constants.Curve25519PrivateKeySize} bytes", nameof(privateKeyBytes));

        Index = index;
        _privateKeyBytes = new byte[Constants.Curve25519PrivateKeySize];
        privateKeyBytes.CopyTo(_privateKeyBytes, 0);

        // Create NSec key for cryptographic operations
        var creationParameters = new KeyCreationParameters
        {
            ExportPolicy = KeyExportPolicies.AllowPlaintextExport
        };

        _nsecKey = Key.Import(KeyAgreementAlgorithm.X25519, _privateKeyBytes, KeyBlobFormat.RawPrivateKey, creationParameters);
        _publicKeyBytes = _nsecKey.PublicKey.Export(KeyBlobFormat.RawPublicKey);
    }

    /// <summary>
    /// Creates a Curve25519 encryption subkey from a seed and creation time.
    /// </summary>
    /// <param name="seed">The seed to derive the key from.</param>
    /// <param name="creationTime">The key creation timestamp.</param>
    /// <param name="index">The subkey index for key cycling (default: 0).</param>
    /// <returns>A new Curve25519Subkey instance.</returns>
    /// <exception cref="ArgumentNullException">Thrown when seed is null.</exception>
    public static Curve25519Subkey CreateEncryptionKey(Seed seed, DateTime creationTime, ushort index = 0)
    {
        ArgumentNullException.ThrowIfNull(seed);

        // First derive the root key using Argon2id
        var rootKey = Argon2Service.DeriveRootKey(seed, creationTime);
        
        try
        {
            // Derive an Ed25519 key first, then convert to Curve25519
            var ed25519KeyBytes = HkdfService.DeriveSubkey(rootKey, SubkeyType.Encryption, index);
            
            try
            {
                // Convert Ed25519 private key to Curve25519 private key
                var curve25519KeyBytes = ConvertEd25519ToCurve25519Private(ed25519KeyBytes);
                
                try
                {
                    return new Curve25519Subkey(curve25519KeyBytes, creationTime, index);
                }
                finally
                {
                    // Clear the converted key bytes
                    curve25519KeyBytes.AsSpan().Clear();
                }
            }
            finally
            {
                // Clear the derived Ed25519 key bytes
                ed25519KeyBytes.AsSpan().Clear();
            }
        }
        finally
        {
            // Clear the root key
            rootKey.AsSpan().Clear();
        }
    }

    /// <summary>
    /// Creates a Curve25519 subkey directly from private key bytes.
    /// This is primarily used for testing or when the key material is already derived.
    /// </summary>
    /// <param name="privateKeyBytes">The Curve25519 private key bytes.</param>
    /// <param name="creationTime">The key creation timestamp.</param>
    /// <param name="index">The subkey index.</param>
    /// <returns>A new Curve25519Subkey instance.</returns>
    /// <exception cref="ArgumentNullException">Thrown when privateKeyBytes is null.</exception>
    /// <exception cref="ArgumentException">Thrown when privateKeyBytes is not 32 bytes.</exception>
    public static Curve25519Subkey FromPrivateKey(byte[] privateKeyBytes, DateTime creationTime, ushort index = 0)
    {
        ArgumentNullException.ThrowIfNull(privateKeyBytes);
        
        if (privateKeyBytes.Length != Constants.Curve25519PrivateKeySize)
        {
            throw new ArgumentException($"Private key must be exactly {Constants.Curve25519PrivateKeySize} bytes", 
                nameof(privateKeyBytes));
        }

        return new Curve25519Subkey(privateKeyBytes, creationTime, index);
    }

    /// <inheritdoc />
    public override byte[] PublicKeyBytes
    {
        get
        {
            ThrowIfDisposed();
            var copy = new byte[_publicKeyBytes.Length];
            _publicKeyBytes.CopyTo(copy, 0);
            return copy;
        }
    }

    /// <inheritdoc />
    public override byte[] PrivateKeyBytes
    {
        get
        {
            ThrowIfDisposed();
            var copy = new byte[_privateKeyBytes.Length];
            _privateKeyBytes.CopyTo(copy, 0);
            return copy;
        }
    }

    /// <inheritdoc />
    public override byte[] Sign(byte[] data)
    {
        // Curve25519 keys cannot sign data - they are for encryption only
        throw new InvalidOperationException("Curve25519 keys cannot be used for signing operations");
    }

    /// <summary>
    /// Performs ECDH key agreement with another public key.
    /// </summary>
    /// <param name="otherPublicKey">The other party's public key.</param>
    /// <returns>The shared secret.</returns>
    /// <exception cref="ArgumentNullException">Thrown when otherPublicKey is null.</exception>
    /// <exception cref="ArgumentException">Thrown when otherPublicKey is not 32 bytes.</exception>
    public byte[] PerformKeyAgreement(byte[] otherPublicKey)
    {
        ArgumentNullException.ThrowIfNull(otherPublicKey);
        ThrowIfDisposed();
        
        if (otherPublicKey.Length != Constants.Curve25519PublicKeySize)
        {
            throw new ArgumentException($"Public key must be exactly {Constants.Curve25519PublicKeySize} bytes", 
                nameof(otherPublicKey));
        }

        var otherKey = PublicKey.Import(KeyAgreementAlgorithm.X25519, otherPublicKey, KeyBlobFormat.RawPublicKey);
        var sharedSecret = KeyAgreementAlgorithm.X25519.Agree(_nsecKey, otherKey);
        
        if (sharedSecret == null)
            throw new InvalidOperationException("Key agreement failed");
            
        return sharedSecret.Export(SharedSecretBlobFormat.RawSharedSecret);
    }

    /// <inheritdoc />
    protected override byte[] ComputeFingerprint()
    {
        ThrowIfDisposed();
        
        // Create the data to hash according to RFC 4880 Section 12.2
        var timestamp = (uint)((DateTimeOffset)CreationTime).ToUnixTimeSeconds();
        var timestampBytes = BitConverter.GetBytes(timestamp);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(timestampBytes);

        // For Curve25519, we need to include the curve OID and key material
        // Build the fingerprint input: version (1 byte) + timestamp (4 bytes) + algorithm (1 byte) + key material length (2 bytes) + curve_oid_length (1 byte) + curve_oid + key_material
        var curveOid = GetCurve25519Oid();
        var keyMaterialLength = (ushort)(1 + curveOid.Length + _publicKeyBytes.Length); // OID length byte + OID + key bytes
        var keyMaterialLengthBytes = BitConverter.GetBytes(keyMaterialLength);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(keyMaterialLengthBytes);

        var fingerprintInput = new byte[1 + 4 + 1 + 2 + 1 + curveOid.Length + _publicKeyBytes.Length];
        var offset = 0;

        fingerprintInput[offset++] = 4; // Version 4
        timestampBytes.CopyTo(fingerprintInput, offset);
        offset += 4;
        fingerprintInput[offset++] = (byte)Algorithm;
        keyMaterialLengthBytes.CopyTo(fingerprintInput, offset);
        offset += 2;
        fingerprintInput[offset++] = (byte)curveOid.Length; // OID length
        curveOid.CopyTo(fingerprintInput, offset);
        offset += curveOid.Length;
        _publicKeyBytes.CopyTo(fingerprintInput, offset);

        using var sha256 = SHA256.Create();
        return sha256.ComputeHash(fingerprintInput);
    }

    /// <summary>
    /// Converts an Ed25519 private key to a Curve25519 private key.
    /// This follows the standard conversion process defined in RFC 7748.
    /// </summary>
    /// <param name="ed25519PrivateKey">The Ed25519 private key bytes.</param>
    /// <returns>The Curve25519 private key bytes.</returns>
    /// <exception cref="ArgumentNullException">Thrown when ed25519PrivateKey is null.</exception>
    /// <exception cref="ArgumentException">Thrown when ed25519PrivateKey is not 32 bytes.</exception>
    private static byte[] ConvertEd25519ToCurve25519Private(byte[] ed25519PrivateKey)
    {
        ArgumentNullException.ThrowIfNull(ed25519PrivateKey);
        
        if (ed25519PrivateKey.Length != 32)
            throw new ArgumentException("Ed25519 private key must be 32 bytes", nameof(ed25519PrivateKey));

        // For Ed25519 -> Curve25519 conversion:
        // 1. Hash the Ed25519 private key with SHA512
        // 2. Take the first 32 bytes
        // 3. Apply clamping: clear bits 0, 1, 2 and 255, set bit 254
        
        using var sha512 = SHA512.Create();
        var hash = sha512.ComputeHash(ed25519PrivateKey);
        
        var curve25519Key = new byte[32];
        Array.Copy(hash, 0, curve25519Key, 0, 32);
        
        // Apply clamping
        curve25519Key[0] &= 0xF8; // Clear bits 0, 1, 2
        curve25519Key[31] &= 0x7F; // Clear bit 255
        curve25519Key[31] |= 0x40; // Set bit 254
        
        // Clear the hash
        hash.AsSpan().Clear();
        
        return curve25519Key;
    }

    /// <summary>
    /// Gets the OID for the Curve25519 curve.
    /// </summary>
    /// <returns>The curve OID bytes.</returns>
    private static byte[] GetCurve25519Oid()
    {
        // OID for Curve25519: 1.3.6.1.4.1.3029.1.5.1 (RFC 6637)
        return new byte[] { 0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01 };
    }

    /// <inheritdoc />
    public override void Dispose()
    {
        if (!IsDisposed())
        {
            // Clear sensitive data
            _privateKeyBytes.AsSpan().Clear();
            _nsecKey?.Dispose();
            _disposed = true;
            base.Dispose();
        }
    }

    /// <summary>
    /// Checks if the key has been disposed.
    /// </summary>
    /// <returns>True if disposed, false otherwise.</returns>
    private bool _disposed = false;
    private bool IsDisposed() => _disposed;

    /// <summary>
    /// Returns a string representation of this subkey.
    /// </summary>
    /// <returns>A string representation including the index.</returns>
    public override string ToString()
    {
        if (IsDisposed())
        {
            return $"Curve25519Subkey(Encryption, index={Index}, disposed)";
        }
        
        var keyIdHex = Convert.ToHexString(KeyId).ToLowerInvariant();
        return $"Curve25519Subkey(Encryption, index={Index}, keyId={keyIdHex[^8..]})";
    }
}