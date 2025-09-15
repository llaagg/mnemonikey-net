using System;
using NSec.Cryptography;

namespace MnemonikeyCs.Pgp.Keys;

/// <summary>
/// Represents the key usage flags for PGP keys.
/// </summary>
[Flags]
public enum KeyUsage : byte
{
    /// <summary>
    /// No usage specified.
    /// </summary>
    None = 0x00,
    
    /// <summary>
    /// Key may be used to certify other keys.
    /// </summary>
    Certify = 0x01,
    
    /// <summary>
    /// Key may be used to sign data.
    /// </summary>
    Sign = 0x02,
    
    /// <summary>
    /// Key may be used to encrypt communications.
    /// </summary>
    EncryptCommunications = 0x04,
    
    /// <summary>
    /// Key may be used to encrypt storage.
    /// </summary>
    EncryptStorage = 0x08,
    
    /// <summary>
    /// The private component of this key may have been split by a secret sharing mechanism.
    /// </summary>
    SplitKey = 0x10,
    
    /// <summary>
    /// Key may be used for authentication.
    /// </summary>
    Authenticate = 0x20,
    
    /// <summary>
    /// The private component of this key may be in the possession of more than one person.
    /// </summary>
    GroupKey = 0x80
}

/// <summary>
/// Represents the algorithm identifiers used in PGP packets.
/// </summary>
public enum PgpAlgorithm : byte
{
    /// <summary>
    /// Ed25519 signature algorithm.
    /// </summary>
    Ed25519 = 22,
    
    /// <summary>
    /// Curve25519 encryption algorithm (ECDH).
    /// </summary>
    Curve25519 = 18
}

/// <summary>
/// Base interface for all PGP keys.
/// </summary>
public interface IPgpKey : IDisposable
{
    /// <summary>
    /// Gets the key creation timestamp.
    /// </summary>
    DateTime CreationTime { get; }
    
    /// <summary>
    /// Gets the PGP algorithm used by this key.
    /// </summary>
    PgpAlgorithm Algorithm { get; }
    
    /// <summary>
    /// Gets the key usage flags.
    /// </summary>
    KeyUsage Usage { get; }
    
    /// <summary>
    /// Gets the public key bytes.
    /// </summary>
    byte[] PublicKeyBytes { get; }
    
    /// <summary>
    /// Gets the private key bytes.
    /// </summary>
    byte[] PrivateKeyBytes { get; }
    
    /// <summary>
    /// Gets the key fingerprint.
    /// </summary>
    byte[] Fingerprint { get; }
    
    /// <summary>
    /// Gets the key ID (last 8 bytes of fingerprint).
    /// </summary>
    byte[] KeyId { get; }
    
    /// <summary>
    /// Signs data with this key.
    /// </summary>
    /// <param name="data">The data to sign.</param>
    /// <returns>The signature bytes.</returns>
    byte[] Sign(byte[] data);
}

/// <summary>
/// Base abstract class for PGP keys providing common functionality.
/// </summary>
public abstract class BaseKey : IPgpKey
{
    private bool _disposed;
    private byte[]? _fingerprint;
    private byte[]? _keyId;

    /// <summary>
    /// Initializes a new instance of the BaseKey class.
    /// </summary>
    /// <param name="creationTime">The key creation timestamp.</param>
    /// <param name="algorithm">The PGP algorithm.</param>
    /// <param name="usage">The key usage flags.</param>
    protected BaseKey(DateTime creationTime, PgpAlgorithm algorithm, KeyUsage usage)
    {
        CreationTime = creationTime;
        Algorithm = algorithm;
        Usage = usage;
    }

    /// <inheritdoc />
    public DateTime CreationTime { get; }

    /// <inheritdoc />
    public PgpAlgorithm Algorithm { get; }

    /// <inheritdoc />
    public KeyUsage Usage { get; }

    /// <inheritdoc />
    public abstract byte[] PublicKeyBytes { get; }

    /// <inheritdoc />
    public abstract byte[] PrivateKeyBytes { get; }

    /// <inheritdoc />
    public virtual byte[] Fingerprint
    {
        get
        {
            ThrowIfDisposed();
            return _fingerprint ??= ComputeFingerprint();
        }
    }

    /// <inheritdoc />
    public virtual byte[] KeyId
    {
        get
        {
            ThrowIfDisposed();
            if (_keyId == null)
            {
                var fingerprint = Fingerprint;
                _keyId = new byte[8];
                Array.Copy(fingerprint, fingerprint.Length - 8, _keyId, 0, 8);
            }
            return _keyId;
        }
    }

    /// <inheritdoc />
    public abstract byte[] Sign(byte[] data);

    /// <summary>
    /// Computes the fingerprint for this key.
    /// </summary>
    /// <returns>The key fingerprint.</returns>
    protected abstract byte[] ComputeFingerprint();

    /// <summary>
    /// Throws an exception if the key has been disposed.
    /// </summary>
    protected void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }

    /// <inheritdoc />
    public virtual void Dispose()
    {
        if (!_disposed)
        {
            // Clear sensitive data
            _fingerprint = null;
            _keyId = null;
            _disposed = true;
        }
    }
}

/// <summary>
/// Base class for Ed25519-based keys.
/// </summary>
public abstract class Ed25519KeyBase : BaseKey
{
    private readonly Key _privateKey;
    private readonly byte[] _publicKeyBytes;
    private readonly byte[] _privateKeyBytes;

    /// <summary>
    /// Initializes a new instance of the Ed25519KeyBase class.
    /// </summary>
    /// <param name="privateKeyBytes">The Ed25519 private key bytes.</param>
    /// <param name="creationTime">The key creation timestamp.</param>
    /// <param name="usage">The key usage flags.</param>
    protected Ed25519KeyBase(byte[] privateKeyBytes, DateTime creationTime, KeyUsage usage)
        : base(creationTime, PgpAlgorithm.Ed25519, usage)
    {
        ArgumentNullException.ThrowIfNull(privateKeyBytes);
        
        if (privateKeyBytes.Length != 32)
            throw new ArgumentException("Ed25519 private key must be 32 bytes", nameof(privateKeyBytes));

        _privateKeyBytes = new byte[32];
        privateKeyBytes.CopyTo(_privateKeyBytes, 0);

        // Create NSec key for cryptographic operations
        var creationParameters = new KeyCreationParameters
        {
            ExportPolicy = KeyExportPolicies.AllowPlaintextExport
        };

        _privateKey = Key.Import(SignatureAlgorithm.Ed25519, _privateKeyBytes, KeyBlobFormat.RawPrivateKey, creationParameters);
        _publicKeyBytes = _privateKey.PublicKey.Export(KeyBlobFormat.RawPublicKey);
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
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(data);
        
        return SignatureAlgorithm.Ed25519.Sign(_privateKey, data);
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

        // Build the fingerprint input: version (1 byte) + timestamp (4 bytes) + algorithm (1 byte) + key material length (2 bytes) + algorithm (1 byte) + key material
        var keyMaterialLength = (ushort)(1 + _publicKeyBytes.Length); // Algorithm byte + key bytes
        var keyMaterialLengthBytes = BitConverter.GetBytes(keyMaterialLength);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(keyMaterialLengthBytes);

        var fingerprintInput = new byte[1 + 4 + 1 + 2 + 1 + _publicKeyBytes.Length];
        var offset = 0;

        fingerprintInput[offset++] = 4; // Version 4
        timestampBytes.CopyTo(fingerprintInput, offset);
        offset += 4;
        fingerprintInput[offset++] = (byte)Algorithm;
        keyMaterialLengthBytes.CopyTo(fingerprintInput, offset);
        offset += 2;
        fingerprintInput[offset++] = (byte)Algorithm; // Algorithm again for key material
        _publicKeyBytes.CopyTo(fingerprintInput, offset);

        using var sha256 = System.Security.Cryptography.SHA256.Create();
        return sha256.ComputeHash(fingerprintInput);
    }

    /// <inheritdoc />
    public override void Dispose()
    {
        if (!IsDisposed())
        {
            // Clear sensitive data
            _privateKeyBytes.AsSpan().Clear();
            _privateKey?.Dispose();
            _disposed = true;
            base.Dispose();
        }
    }

    /// <summary>
    /// Checks if the key has been disposed.
    /// </summary>
    /// <returns>True if disposed, false otherwise.</returns>
    private bool _disposed = false;
    protected bool IsDisposed() => _disposed;
}