using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using MnemonikeyCs.Pgp.Keys;

namespace MnemonikeyCs.Pgp.Packets;

/// <summary>
/// Represents an OpenPGP signature packet.
/// </summary>
public sealed class SignaturePacket
{
    private readonly List<(SignatureSubpacketType type, byte[] data, bool critical)> _hashedSubpackets;
    private readonly List<(SignatureSubpacketType type, byte[] data, bool critical)> _unhashedSubpackets;

    /// <summary>
    /// Gets the signature version (always 4 for this implementation).
    /// </summary>
    public byte Version => 4;

    /// <summary>
    /// Gets the signature type.
    /// </summary>
    public SignatureType SignatureType { get; }

    /// <summary>
    /// Gets the public key algorithm.
    /// </summary>
    public PgpAlgorithm PublicKeyAlgorithm { get; }

    /// <summary>
    /// Gets the hash algorithm.
    /// </summary>
    public HashAlgorithm HashAlgorithm { get; }

    /// <summary>
    /// Gets the signature creation time.
    /// </summary>
    public DateTime CreationTime { get; }

    /// <summary>
    /// Gets the issuer key ID.
    /// </summary>
    public byte[] IssuerKeyId { get; }

    /// <summary>
    /// Gets the signature bytes.
    /// </summary>
    public byte[] SignatureBytes { get; private set; } = Array.Empty<byte>();

    /// <summary>
    /// Initializes a new instance of the SignaturePacket class.
    /// </summary>
    /// <param name="signatureType">The signature type.</param>
    /// <param name="publicKeyAlgorithm">The public key algorithm.</param>
    /// <param name="hashAlgorithm">The hash algorithm.</param>
    /// <param name="creationTime">The signature creation time.</param>
    /// <param name="issuerKeyId">The issuer key ID.</param>
    public SignaturePacket(SignatureType signatureType, PgpAlgorithm publicKeyAlgorithm, 
        HashAlgorithm hashAlgorithm, DateTime creationTime, byte[] issuerKeyId)
    {
        ArgumentNullException.ThrowIfNull(issuerKeyId);
        
        if (issuerKeyId.Length != 8)
            throw new ArgumentException("Issuer key ID must be 8 bytes", nameof(issuerKeyId));

        SignatureType = signatureType;
        PublicKeyAlgorithm = publicKeyAlgorithm;
        HashAlgorithm = hashAlgorithm;
        CreationTime = creationTime;
        IssuerKeyId = new byte[8];
        issuerKeyId.CopyTo(IssuerKeyId, 0);

        _hashedSubpackets = new List<(SignatureSubpacketType, byte[], bool)>();
        _unhashedSubpackets = new List<(SignatureSubpacketType, byte[], bool)>();

        // Add required subpackets
        AddHashedSubpacket(SignatureSubpacketType.SignatureCreationTime, 
            PacketSerializer.CreateSignatureCreationTimeSubpacket(creationTime));
        AddUnhashedSubpacket(SignatureSubpacketType.Issuer,
            PacketSerializer.CreateIssuerSubpacket(issuerKeyId));
    }

    /// <summary>
    /// Adds a hashed subpacket.
    /// </summary>
    /// <param name="type">The subpacket type.</param>
    /// <param name="data">The subpacket data.</param>
    /// <param name="critical">Whether the subpacket is critical.</param>
    public void AddHashedSubpacket(SignatureSubpacketType type, byte[] data, bool critical = false)
    {
        ArgumentNullException.ThrowIfNull(data);
        _hashedSubpackets.Add((type, data, critical));
    }

    /// <summary>
    /// Adds an unhashed subpacket.
    /// </summary>
    /// <param name="type">The subpacket type.</param>
    /// <param name="data">The subpacket data.</param>
    /// <param name="critical">Whether the subpacket is critical.</param>
    public void AddUnhashedSubpacket(SignatureSubpacketType type, byte[] data, bool critical = false)
    {
        ArgumentNullException.ThrowIfNull(data);
        _unhashedSubpackets.Add((type, data, critical));
    }

    /// <summary>
    /// Computes and sets the signature for the specified data and signing key.
    /// </summary>
    /// <param name="dataToSign">The data to sign.</param>
    /// <param name="signingKey">The key to use for signing.</param>
    public void ComputeSignature(byte[] dataToSign, IPgpKey signingKey)
    {
        ArgumentNullException.ThrowIfNull(dataToSign);
        ArgumentNullException.ThrowIfNull(signingKey);

        // Build the signature data according to RFC 4880 Section 5.2.4
        using var signatureData = new MemoryStream();

        // Write the data to sign
        signatureData.Write(dataToSign);

        // Write the signature packet data for hashing
        WriteSignatureDataForHashing(signatureData);

        // Write the trailer
        WriteSignatureTrailer(signatureData);

        var fullSignatureData = signatureData.ToArray();

        // Compute the hash
        byte[] hash = ComputeHash(fullSignatureData);

        // Sign the hash
        SignatureBytes = signingKey.Sign(hash);
    }

    /// <summary>
    /// Serializes the signature packet to a byte array.
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
        PacketSerializer.WritePacketHeader(finalOutput, PacketType.Signature, packetBody.Length);
        finalOutput.Write(packetBody);
        
        return finalOutput.ToArray();
    }

    /// <summary>
    /// Creates a self-certification signature for a master key and user ID.
    /// </summary>
    /// <param name="masterKey">The master key.</param>
    /// <param name="userId">The user ID.</param>
    /// <param name="keyFlags">The key usage flags.</param>
    /// <returns>A new SignaturePacket instance.</returns>
    public static SignaturePacket CreateSelfCertification(Ed25519MasterKey masterKey, string userId, byte keyFlags = 0x03)
    {
        ArgumentNullException.ThrowIfNull(masterKey);
        ArgumentNullException.ThrowIfNull(userId);

        var signature = new SignaturePacket(
            SignatureType.PositiveCertification,
            PgpAlgorithm.Ed25519,
            HashAlgorithm.SHA256,
            masterKey.CreationTime,
            masterKey.KeyId);

        // Add key flags subpacket
        signature.AddHashedSubpacket(SignatureSubpacketType.KeyFlags,
            PacketSerializer.CreateKeyFlagsSubpacket(keyFlags), critical: true);

        // Add preferred algorithms
        signature.AddHashedSubpacket(SignatureSubpacketType.PreferredHashAlgorithms,
            PacketSerializer.CreatePreferredHashAlgorithmsSubpacket(
                HashAlgorithm.SHA256, HashAlgorithm.SHA384, HashAlgorithm.SHA512));

        signature.AddHashedSubpacket(SignatureSubpacketType.PreferredSymmetricAlgorithms,
            PacketSerializer.CreatePreferredSymmetricAlgorithmsSubpacket(
                SymmetricAlgorithm.AES256, SymmetricAlgorithm.AES192, SymmetricAlgorithm.AES128));

        signature.AddHashedSubpacket(SignatureSubpacketType.PreferredCompressionAlgorithms,
            PacketSerializer.CreatePreferredCompressionAlgorithmsSubpacket(
                CompressionAlgorithm.ZLIB, CompressionAlgorithm.ZIP, CompressionAlgorithm.Uncompressed));

        // Compute signature
        var signatureData = BuildSelfCertificationData(masterKey, userId);
        signature.ComputeSignature(signatureData, masterKey);

        return signature;
    }

    /// <summary>
    /// Creates a subkey binding signature.
    /// </summary>
    /// <param name="masterKey">The master key.</param>
    /// <param name="subkey">The subkey.</param>
    /// <param name="keyFlags">The subkey usage flags.</param>
    /// <returns>A new SignaturePacket instance.</returns>
    public static SignaturePacket CreateSubkeyBinding(Ed25519MasterKey masterKey, IPgpKey subkey, byte keyFlags)
    {
        ArgumentNullException.ThrowIfNull(masterKey);
        ArgumentNullException.ThrowIfNull(subkey);

        var signature = new SignaturePacket(
            SignatureType.SubkeyBinding,
            PgpAlgorithm.Ed25519,
            HashAlgorithm.SHA256,
            subkey.CreationTime,
            masterKey.KeyId);

        // Add key flags subpacket
        signature.AddHashedSubpacket(SignatureSubpacketType.KeyFlags,
            PacketSerializer.CreateKeyFlagsSubpacket(keyFlags), critical: true);

        // Compute signature
        var signatureData = BuildSubkeyBindingData(masterKey, subkey);
        signature.ComputeSignature(signatureData, masterKey);

        return signature;
    }

    /// <summary>
    /// Builds the signature data for self-certification.
    /// </summary>
    /// <param name="masterKey">The master key.</param>
    /// <param name="userId">The user ID.</param>
    /// <returns>The data to sign.</returns>
    private static byte[] BuildSelfCertificationData(Ed25519MasterKey masterKey, string userId)
    {
        using var output = new MemoryStream();

        // Write public key packet data
        WritePublicKeyPacketData(output, masterKey);

        // Write user ID packet data
        output.WriteByte(0xB4); // User ID packet type for signature calculation
        var userIdBytes = System.Text.Encoding.UTF8.GetBytes(userId);
        PacketSerializer.WriteUInt32(output, (uint)userIdBytes.Length);
        output.Write(userIdBytes);

        return output.ToArray();
    }

    /// <summary>
    /// Builds the signature data for subkey binding.
    /// </summary>
    /// <param name="masterKey">The master key.</param>
    /// <param name="subkey">The subkey.</param>
    /// <returns>The data to sign.</returns>
    private static byte[] BuildSubkeyBindingData(Ed25519MasterKey masterKey, IPgpKey subkey)
    {
        using var output = new MemoryStream();

        // Write master key packet data
        WritePublicKeyPacketData(output, masterKey);

        // Write subkey packet data
        WritePublicKeyPacketData(output, subkey);

        return output.ToArray();
    }

    /// <summary>
    /// Writes public key packet data for signature calculation.
    /// </summary>
    /// <param name="output">The output stream.</param>
    /// <param name="key">The key.</param>
    private static void WritePublicKeyPacketData(Stream output, IPgpKey key)
    {
        output.WriteByte(0x99); // Public key packet type for signature calculation

        using var keyData = new MemoryStream();
        keyData.WriteByte(4); // Version
        PacketSerializer.WriteTimestamp(keyData, key.CreationTime);
        keyData.WriteByte((byte)key.Algorithm);

        if (key.Algorithm == PgpAlgorithm.Ed25519)
        {
            // Ed25519: algorithm byte + key data
            PacketSerializer.WriteMPI(keyData, new byte[] { (byte)key.Algorithm }.Concat(key.PublicKeyBytes).ToArray());
        }
        else if (key.Algorithm == PgpAlgorithm.Curve25519)
        {
            // Curve25519: OID + key data
            var curve25519Key = (Curve25519Subkey)key;
            var oid = new byte[] { 0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01 };
            keyData.WriteByte((byte)oid.Length);
            keyData.Write(oid);
            PacketSerializer.WriteMPI(keyData, key.PublicKeyBytes);
        }

        var keyDataBytes = keyData.ToArray();
        PacketSerializer.WriteUInt16(output, (ushort)keyDataBytes.Length);
        output.Write(keyDataBytes);
    }

    /// <summary>
    /// Writes the signature packet body.
    /// </summary>
    /// <param name="output">The output stream.</param>
    private void WritePacketBody(Stream output)
    {
        output.WriteByte(Version);
        output.WriteByte((byte)SignatureType);
        output.WriteByte((byte)PublicKeyAlgorithm);
        output.WriteByte((byte)HashAlgorithm);

        // Write hashed subpackets
        var hashedSubpacketsLength = PacketSerializer.CalculateSubpacketsLength(_hashedSubpackets);
        PacketSerializer.WriteUInt16(output, (ushort)hashedSubpacketsLength);
        PacketSerializer.WriteSubpackets(output, _hashedSubpackets);

        // Write unhashed subpackets
        var unhashedSubpacketsLength = PacketSerializer.CalculateSubpacketsLength(_unhashedSubpackets);
        PacketSerializer.WriteUInt16(output, (ushort)unhashedSubpacketsLength);
        PacketSerializer.WriteSubpackets(output, _unhashedSubpackets);

        // Write first two bytes of hash
        var hash = ComputeHashForLeftBytes();
        output.WriteByte(hash[0]);
        output.WriteByte(hash[1]);

        // Write signature
        PacketSerializer.WriteMPI(output, SignatureBytes);
    }

    /// <summary>
    /// Writes signature data for hashing.
    /// </summary>
    /// <param name="output">The output stream.</param>
    private void WriteSignatureDataForHashing(Stream output)
    {
        output.WriteByte(Version);
        output.WriteByte((byte)SignatureType);
        output.WriteByte((byte)PublicKeyAlgorithm);
        output.WriteByte((byte)HashAlgorithm);

        // Write hashed subpackets
        var hashedSubpacketsLength = PacketSerializer.CalculateSubpacketsLength(_hashedSubpackets);
        PacketSerializer.WriteUInt16(output, (ushort)hashedSubpacketsLength);
        PacketSerializer.WriteSubpackets(output, _hashedSubpackets);
    }

    /// <summary>
    /// Writes the signature trailer.
    /// </summary>
    /// <param name="output">The output stream.</param>
    private void WriteSignatureTrailer(Stream output)
    {
        output.WriteByte(Version);
        output.WriteByte(0xFF);

        // Write length of hashed data
        var hashedDataLength = 6 + PacketSerializer.CalculateSubpacketsLength(_hashedSubpackets); // 6 = version + type + pub_key_alg + hash_alg + hashed_length
        PacketSerializer.WriteUInt32(output, (uint)hashedDataLength);
    }

    /// <summary>
    /// Computes the hash of the given data.
    /// </summary>
    /// <param name="data">The data to hash.</param>
    /// <returns>The hash bytes.</returns>
    private byte[] ComputeHash(byte[] data)
    {
        return HashAlgorithm switch
        {
            HashAlgorithm.SHA256 => SHA256.HashData(data),
            HashAlgorithm.SHA384 => SHA384.HashData(data),
            HashAlgorithm.SHA512 => SHA512.HashData(data),
            _ => throw new NotSupportedException($"Hash algorithm {HashAlgorithm} is not supported")
        };
    }

    /// <summary>
    /// Computes hash for the left two bytes verification.
    /// </summary>
    /// <returns>The hash bytes.</returns>
    private byte[] ComputeHashForLeftBytes()
    {
        // For now, return zeros - this would need proper implementation with the actual signed data
        var hash = new byte[32];
        return hash;
    }
}