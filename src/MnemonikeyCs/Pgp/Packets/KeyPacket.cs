using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using MnemonikeyCs.Pgp.Keys;

namespace MnemonikeyCs.Pgp.Packets;

/// <summary>
/// Represents an OpenPGP key packet (public key, secret key, or subkey).
/// </summary>
public sealed class KeyPacket
{
    /// <summary>
    /// Gets the packet version (always 4 for this implementation).
    /// </summary>
    public byte Version => 4;

    /// <summary>
    /// Gets the key creation timestamp.
    /// </summary>
    public DateTime CreationTime { get; }

    /// <summary>
    /// Gets the public key algorithm.
    /// </summary>
    public PgpAlgorithm Algorithm { get; }

    /// <summary>
    /// Gets the public key bytes.
    /// </summary>
    public byte[] PublicKeyBytes { get; }

    /// <summary>
    /// Gets the private key bytes (null for public key packets).
    /// </summary>
    public byte[]? PrivateKeyBytes { get; }

    /// <summary>
    /// Gets the packet type.
    /// </summary>
    public PacketType PacketType { get; }

    /// <summary>
    /// Gets whether this is a public key packet (no private key material).
    /// </summary>
    public bool IsPublic => PrivateKeyBytes == null;

    /// <summary>
    /// Gets whether this is a master key (not a subkey).
    /// </summary>
    public bool IsMasterKey => PacketType is PacketType.PublicKey or PacketType.SecretKey;

    /// <summary>
    /// Initializes a new instance of the KeyPacket class for a public key.
    /// </summary>
    /// <param name="key">The PGP key.</param>
    /// <param name="isMasterKey">Whether this is a master key (true) or subkey (false).</param>
    private KeyPacket(IPgpKey key, bool isMasterKey)
    {
        ArgumentNullException.ThrowIfNull(key);

        CreationTime = key.CreationTime;
        Algorithm = key.Algorithm;
        PublicKeyBytes = key.PublicKeyBytes;
        PrivateKeyBytes = null;

        PacketType = isMasterKey ? PacketType.PublicKey : PacketType.PublicSubkey;
    }

    /// <summary>
    /// Initializes a new instance of the KeyPacket class for a secret key.
    /// </summary>
    /// <param name="key">The PGP key.</param>
    /// <param name="isMasterKey">Whether this is a master key (true) or subkey (false).</param>
    /// <param name="includePrivate">Whether to include private key material.</param>
    private KeyPacket(IPgpKey key, bool isMasterKey, bool includePrivate)
    {
        ArgumentNullException.ThrowIfNull(key);

        CreationTime = key.CreationTime;
        Algorithm = key.Algorithm;
        PublicKeyBytes = key.PublicKeyBytes;
        
        if (includePrivate)
        {
            PrivateKeyBytes = key.PrivateKeyBytes;
            PacketType = isMasterKey ? PacketType.SecretKey : PacketType.SecretSubkey;
        }
        else
        {
            PrivateKeyBytes = null;
            PacketType = isMasterKey ? PacketType.PublicKey : PacketType.PublicSubkey;
        }
    }

    /// <summary>
    /// Creates a public key packet from a PGP key.
    /// </summary>
    /// <param name="key">The PGP key.</param>
    /// <param name="isMasterKey">Whether this is a master key.</param>
    /// <returns>A new KeyPacket instance.</returns>
    public static KeyPacket CreatePublicKey(IPgpKey key, bool isMasterKey = true)
    {
        return new KeyPacket(key, isMasterKey);
    }

    /// <summary>
    /// Creates a secret key packet from a PGP key.
    /// </summary>
    /// <param name="key">The PGP key.</param>
    /// <param name="isMasterKey">Whether this is a master key.</param>
    /// <returns>A new KeyPacket instance.</returns>
    public static KeyPacket CreateSecretKey(IPgpKey key, bool isMasterKey = true)
    {
        return new KeyPacket(key, isMasterKey, includePrivate: true);
    }

    /// <summary>
    /// Creates a public subkey packet from a PGP key.
    /// </summary>
    /// <param name="subkey">The PGP subkey.</param>
    /// <returns>A new KeyPacket instance.</returns>
    public static KeyPacket CreatePublicSubkey(IPgpKey subkey)
    {
        return new KeyPacket(subkey, isMasterKey: false);
    }

    /// <summary>
    /// Creates a secret subkey packet from a PGP key.
    /// </summary>
    /// <param name="subkey">The PGP subkey.</param>
    /// <returns>A new KeyPacket instance.</returns>
    public static KeyPacket CreateSecretSubkey(IPgpKey subkey)
    {
        return new KeyPacket(subkey, isMasterKey: false, includePrivate: true);
    }

    /// <summary>
    /// Serializes the key packet to a byte array.
    /// </summary>
    /// <returns>The serialized packet data.</returns>
    public byte[] Serialize()
    {
        using var output = new MemoryStream();
        
        // Write packet body
        WritePacketBody(output);
        
        var packetBody = output.ToArray();
        
        // Create final packet with header
        using var finalOutput = new MemoryStream();
        PacketSerializer.WritePacketHeader(finalOutput, PacketType, packetBody.Length);
        finalOutput.Write(packetBody);
        
        return finalOutput.ToArray();
    }

    /// <summary>
    /// Serializes only the public key portion of the packet.
    /// </summary>
    /// <returns>The serialized public key data.</returns>
    public byte[] SerializePublicKey()
    {
        using var output = new MemoryStream();
        WritePublicKeyMaterial(output);
        return output.ToArray();
    }

    /// <summary>
    /// Computes the key fingerprint according to RFC 4880.
    /// </summary>
    /// <returns>The 20-byte (SHA-1) or 32-byte (SHA-256) fingerprint.</returns>
    public byte[] ComputeFingerprint()
    {
        using var output = new MemoryStream();

        // Write the public key packet data for fingerprint calculation
        output.WriteByte(0x99); // Packet tag for fingerprint calculation

        using var keyData = new MemoryStream();
        WritePublicKeyMaterial(keyData);
        
        var keyDataBytes = keyData.ToArray();
        PacketSerializer.WriteUInt16(output, (ushort)keyDataBytes.Length);
        output.Write(keyDataBytes);

        var fingerprintData = output.ToArray();

        // Use SHA-256 for fingerprint (can be changed to SHA-1 for compatibility)
        using var sha256 = SHA256.Create();
        return sha256.ComputeHash(fingerprintData);
    }

    /// <summary>
    /// Gets the key ID (last 8 bytes of fingerprint).
    /// </summary>
    /// <returns>The 8-byte key ID.</returns>
    public byte[] GetKeyId()
    {
        var fingerprint = ComputeFingerprint();
        var keyId = new byte[8];
        Array.Copy(fingerprint, fingerprint.Length - 8, keyId, 0, 8);
        return keyId;
    }

    /// <summary>
    /// Writes the packet body to the output stream.
    /// </summary>
    /// <param name="output">The output stream.</param>
    private void WritePacketBody(Stream output)
    {
        // Write public key material
        WritePublicKeyMaterial(output);

        // Write private key material if this is a secret key
        if (!IsPublic && PrivateKeyBytes != null)
        {
            WritePrivateKeyMaterial(output);
        }
    }

    /// <summary>
    /// Writes the public key material to the output stream.
    /// </summary>
    /// <param name="output">The output stream.</param>
    private void WritePublicKeyMaterial(Stream output)
    {
        output.WriteByte(Version);
        PacketSerializer.WriteTimestamp(output, CreationTime);
        output.WriteByte((byte)Algorithm);

        if (Algorithm == PgpAlgorithm.Ed25519)
        {
            WriteEd25519PublicKey(output);
        }
        else if (Algorithm == PgpAlgorithm.Curve25519)
        {
            WriteCurve25519PublicKey(output);
        }
        else
        {
            throw new NotSupportedException($"Algorithm {Algorithm} is not supported");
        }
    }

    /// <summary>
    /// Writes Ed25519 public key material.
    /// </summary>
    /// <param name="output">The output stream.</param>
    private void WriteEd25519PublicKey(Stream output)
    {
        // For Ed25519, write the key as MPI prefixed with algorithm identifier
        var keyWithAlg = new byte[] { (byte)Algorithm }.Concat(PublicKeyBytes).ToArray();
        PacketSerializer.WriteMPI(output, keyWithAlg);
    }

    /// <summary>
    /// Writes Curve25519 public key material.
    /// </summary>
    /// <param name="output">The output stream.</param>
    private void WriteCurve25519PublicKey(Stream output)
    {
        // For Curve25519 (ECDH), write OID and key point
        var oid = new byte[] { 0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01 };
        
        // Write OID length and OID
        output.WriteByte((byte)oid.Length);
        output.Write(oid);
        
        // Write key point as MPI
        PacketSerializer.WriteMPI(output, PublicKeyBytes);
        
        // Write KDF parameters (for ECDH)
        WriteKdfParameters(output);
    }

    /// <summary>
    /// Writes KDF parameters for ECDH keys.
    /// </summary>
    /// <param name="output">The output stream.</param>
    private void WriteKdfParameters(Stream output)
    {
        // KDF parameters: hash algorithm (SHA-256) + symmetric algorithm (AES-256)
        output.WriteByte(3); // Length of KDF parameters
        output.WriteByte(1); // Reserved byte
        output.WriteByte((byte)HashAlgorithm.SHA256);
        output.WriteByte((byte)SymmetricAlgorithm.AES256);
    }

    /// <summary>
    /// Writes the private key material to the output stream.
    /// </summary>
    /// <param name="output">The output stream.</param>
    private void WritePrivateKeyMaterial(Stream output)
    {
        if (PrivateKeyBytes == null)
            throw new InvalidOperationException("No private key material available");

        // String-to-Key usage: 0 = unencrypted
        output.WriteByte(0);

        if (Algorithm == PgpAlgorithm.Ed25519)
        {
            WriteEd25519PrivateKey(output);
        }
        else if (Algorithm == PgpAlgorithm.Curve25519)
        {
            WriteCurve25519PrivateKey(output);
        }

        // Write checksum (simple checksum of private key material)
        WritePrivateKeyChecksum(output);
    }

    /// <summary>
    /// Writes Ed25519 private key material.
    /// </summary>
    /// <param name="output">The output stream.</param>
    private void WriteEd25519PrivateKey(Stream output)
    {
        // Write private key as MPI
        PacketSerializer.WriteMPI(output, PrivateKeyBytes!);
    }

    /// <summary>
    /// Writes Curve25519 private key material.
    /// </summary>
    /// <param name="output">The output stream.</param>
    private void WriteCurve25519PrivateKey(Stream output)
    {
        // Write private key as MPI
        PacketSerializer.WriteMPI(output, PrivateKeyBytes!);
    }

    /// <summary>
    /// Writes the private key checksum.
    /// </summary>
    /// <param name="output">The output stream.</param>
    private void WritePrivateKeyChecksum(Stream output)
    {
        if (PrivateKeyBytes == null)
            throw new InvalidOperationException("No private key material available");

        // Simple checksum: sum of all private key bytes mod 65536
        uint checksum = 0;
        foreach (byte b in PrivateKeyBytes)
        {
            checksum = (checksum + b) % 65536;
        }

        PacketSerializer.WriteUInt16(output, (ushort)checksum);
    }
}