using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using MnemonikeyCs.Core;
using MnemonikeyCs.Pgp.Keys;
using MnemonikeyCs.Pgp.Packets;

namespace MnemonikeyCs.Pgp;

/// <summary>
/// Represents a complete PGP key set containing a master key and subkeys.
/// </summary>
public sealed class KeySet : IDisposable
{
    private readonly List<IPgpKey> _subkeys;
    private readonly List<SignaturePacket> _signatures;
    private bool _disposed;

    /// <summary>
    /// Gets the master certification key.
    /// </summary>
    public Ed25519MasterKey MasterKey { get; }

    /// <summary>
    /// Gets the primary User ID for this key set.
    /// </summary>
    public UserId PrimaryUserId { get; }

    /// <summary>
    /// Gets the creation time of the key set (same as master key creation time).
    /// </summary>
    public DateTime CreationTime => MasterKey.CreationTime;

    /// <summary>
    /// Gets the master key fingerprint.
    /// </summary>
    public byte[] Fingerprint => MasterKey.Fingerprint;

    /// <summary>
    /// Gets the master key ID.
    /// </summary>
    public byte[] KeyId => MasterKey.KeyId;

    /// <summary>
    /// Gets all subkeys in this key set.
    /// </summary>
    public IReadOnlyList<IPgpKey> Subkeys => _subkeys.AsReadOnly();

    /// <summary>
    /// Gets all signatures in this key set.
    /// </summary>
    public IReadOnlyList<SignaturePacket> Signatures => _signatures.AsReadOnly();

    /// <summary>
    /// Initializes a new instance of the KeySet class.
    /// </summary>
    /// <param name="masterKey">The master certification key.</param>
    /// <param name="primaryUserId">The primary User ID.</param>
    private KeySet(Ed25519MasterKey masterKey, UserId primaryUserId)
    {
        MasterKey = masterKey;
        PrimaryUserId = primaryUserId;
        _subkeys = new List<IPgpKey>();
        _signatures = new List<SignaturePacket>();
    }

    /// <summary>
    /// Creates a complete key set from a seed.
    /// </summary>
    /// <param name="seed">The seed to derive keys from.</param>
    /// <param name="userId">The primary User ID.</param>
    /// <param name="encryptionIndex">The encryption subkey index (default: 0).</param>
    /// <param name="signingIndex">The signing subkey index (default: 0).</param>
    /// <param name="authenticationIndex">The authentication subkey index (default: 0).</param>
    /// <returns>A new KeySet instance with all keys and signatures.</returns>
    public static KeySet Create(
        Seed seed, 
        UserId userId, 
        ushort encryptionIndex = 0,
        ushort signingIndex = 0,
        ushort authenticationIndex = 0)
    {
        ArgumentNullException.ThrowIfNull(seed);
        ArgumentNullException.ThrowIfNull(userId);

        var creationTime = DateTime.UtcNow;
        
        // Create master key
        var masterKey = Ed25519MasterKey.FromSeed(seed, creationTime);
        var keySet = new KeySet(masterKey, userId);

        // Create subkeys
        var encryptionKey = Curve25519Subkey.CreateEncryptionKey(seed, creationTime, encryptionIndex);
        var signingKey = Ed25519Subkey.CreateSigningKey(seed, creationTime, signingIndex);
        var authenticationKey = Ed25519Subkey.CreateAuthenticationKey(seed, creationTime, authenticationIndex);

        keySet.AddSubkey(encryptionKey);
        keySet.AddSubkey(signingKey);
        keySet.AddSubkey(authenticationKey);

        // Create signatures
        keySet.CreateSelfCertification();
        keySet.CreateSubkeyBindings();

        return keySet;
    }

    /// <summary>
    /// Creates a key set from an existing master key.
    /// </summary>
    /// <param name="masterKey">The master key.</param>
    /// <param name="userId">The primary User ID.</param>
    /// <returns>A new KeySet instance.</returns>
    public static KeySet FromMasterKey(Ed25519MasterKey masterKey, UserId userId)
    {
        ArgumentNullException.ThrowIfNull(masterKey);
        ArgumentNullException.ThrowIfNull(userId);

        return new KeySet(masterKey, userId);
    }

    /// <summary>
    /// Adds a subkey to the key set.
    /// </summary>
    /// <param name="subkey">The subkey to add.</param>
    public void AddSubkey(IPgpKey subkey)
    {
        ArgumentNullException.ThrowIfNull(subkey);
        ThrowIfDisposed();

        if (!_subkeys.Contains(subkey))
        {
            _subkeys.Add(subkey);
        }
    }

    /// <summary>
    /// Removes a subkey from the key set.
    /// </summary>
    /// <param name="subkey">The subkey to remove.</param>
    /// <returns>True if the subkey was removed, false if it wasn't found.</returns>
    public bool RemoveSubkey(IPgpKey subkey)
    {
        ThrowIfDisposed();
        return _subkeys.Remove(subkey);
    }

    /// <summary>
    /// Gets the encryption subkey.
    /// </summary>
    /// <returns>The encryption subkey, or null if not found.</returns>
    public Curve25519Subkey? GetEncryptionKey()
    {
        ThrowIfDisposed();
        return _subkeys.OfType<Curve25519Subkey>().FirstOrDefault();
    }

    /// <summary>
    /// Gets the signing subkey.
    /// </summary>
    /// <returns>The signing subkey, or null if not found.</returns>
    public Ed25519Subkey? GetSigningKey()
    {
        ThrowIfDisposed();
        return _subkeys.OfType<Ed25519Subkey>().FirstOrDefault(k => k.SubkeyType == SubkeyType.Signing);
    }

    /// <summary>
    /// Gets the authentication subkey.
    /// </summary>
    /// <returns>The authentication subkey, or null if not found.</returns>
    public Ed25519Subkey? GetAuthenticationKey()
    {
        ThrowIfDisposed();
        return _subkeys.OfType<Ed25519Subkey>().FirstOrDefault(k => k.SubkeyType == SubkeyType.Authentication);
    }

    /// <summary>
    /// Creates the self-certification signature for the master key and primary User ID.
    /// </summary>
    private void CreateSelfCertification()
    {
        var signature = SignaturePacket.CreateSelfCertification(MasterKey, PrimaryUserId.Value);
        _signatures.Add(signature);
    }

    /// <summary>
    /// Creates subkey binding signatures for all subkeys.
    /// </summary>
    private void CreateSubkeyBindings()
    {
        foreach (var subkey in _subkeys)
        {
            byte keyFlags = subkey.Usage switch
            {
                KeyUsage.EncryptCommunications | KeyUsage.EncryptStorage => 0x0C, // Encrypt communications + storage
                KeyUsage.Sign => 0x02, // Sign data
                KeyUsage.Authenticate => 0x20, // Authentication
                _ => 0x00
            };

            var signature = SignaturePacket.CreateSubkeyBinding(MasterKey, subkey, keyFlags);
            _signatures.Add(signature);
        }
    }

    /// <summary>
    /// Exports the key set as ASCII armored PGP public key.
    /// </summary>
    /// <returns>The ASCII armored public key.</returns>
    public string ExportPublicKeyArmored()
    {
        ThrowIfDisposed();
        var binaryData = ExportPublicKeyBinary();
        return ArmorData("PGP PUBLIC KEY BLOCK", binaryData);
    }

    /// <summary>
    /// Exports the key set as binary PGP public key.
    /// </summary>
    /// <returns>The binary public key data.</returns>
    public byte[] ExportPublicKeyBinary()
    {
        ThrowIfDisposed();

        using var output = new MemoryStream();

        // Write master public key packet
        var masterKeyPacket = KeyPacket.CreatePublicKey(MasterKey);
        output.Write(masterKeyPacket.Serialize());

        // Write User ID packet
        var userIdPacket = new UserIdPacket(PrimaryUserId.Value);
        output.Write(userIdPacket.Serialize());

        // Write self-certification signature
        var selfCertSignature = _signatures.FirstOrDefault(s => s.SignatureType == SignatureType.PositiveCertification);
        if (selfCertSignature != null)
        {
            output.Write(selfCertSignature.Serialize());
        }

        // Write subkeys and their binding signatures
        var subkeySignatures = _signatures.Where(s => s.SignatureType == SignatureType.SubkeyBinding).ToList();
        
        for (int i = 0; i < _subkeys.Count; i++)
        {
            var subkey = _subkeys[i];
            var subkeyPacket = KeyPacket.CreatePublicSubkey(subkey);
            output.Write(subkeyPacket.Serialize());

            // Write corresponding binding signature
            if (i < subkeySignatures.Count)
            {
                output.Write(subkeySignatures[i].Serialize());
            }
        }

        return output.ToArray();
    }

    /// <summary>
    /// Exports the key set as ASCII armored PGP private key.
    /// </summary>
    /// <param name="password">Optional password for encryption (null for unencrypted).</param>
    /// <returns>The ASCII armored private key.</returns>
    public string ExportPrivateKeyArmored(string? password = null)
    {
        ThrowIfDisposed();
        var binaryData = ExportPrivateKeyBinary(password);
        return ArmorData("PGP PRIVATE KEY BLOCK", binaryData);
    }

    /// <summary>
    /// Exports the key set as binary PGP private key.
    /// </summary>
    /// <param name="password">Optional password for encryption (null for unencrypted).</param>
    /// <returns>The binary private key data.</returns>
    public byte[] ExportPrivateKeyBinary(string? password = null)
    {
        ThrowIfDisposed();

        using var output = new MemoryStream();

        // Write master secret key packet
        var masterKeyPacket = KeyPacket.CreateSecretKey(MasterKey);
        if (password != null)
        {
            throw new NotImplementedException("Password-protected private keys are not yet implemented");
        }
        output.Write(masterKeyPacket.Serialize());

        // Write User ID packet
        var userIdPacket = new UserIdPacket(PrimaryUserId.Value);
        output.Write(userIdPacket.Serialize());

        // Write self-certification signature
        var selfCertSignature = _signatures.FirstOrDefault(s => s.SignatureType == SignatureType.PositiveCertification);
        if (selfCertSignature != null)
        {
            output.Write(selfCertSignature.Serialize());
        }

        // Write secret subkeys and their binding signatures
        var subkeySignatures = _signatures.Where(s => s.SignatureType == SignatureType.SubkeyBinding).ToList();
        
        for (int i = 0; i < _subkeys.Count; i++)
        {
            var subkey = _subkeys[i];
            var subkeyPacket = KeyPacket.CreateSecretSubkey(subkey);
            output.Write(subkeyPacket.Serialize());

            // Write corresponding binding signature
            if (i < subkeySignatures.Count)
            {
                output.Write(subkeySignatures[i].Serialize());
            }
        }

        return output.ToArray();
    }

    /// <summary>
    /// Gets a summary of the key set for display purposes.
    /// </summary>
    /// <returns>A string summary of the key set.</returns>
    public string GetSummary()
    {
        ThrowIfDisposed();

        var sb = new StringBuilder();
        sb.AppendLine($"Master Key: Ed25519 ({Convert.ToHexString(KeyId).ToLowerInvariant()})");
        sb.AppendLine($"User ID: {PrimaryUserId}");
        sb.AppendLine($"Created: {CreationTime:yyyy-MM-dd HH:mm:ss} UTC");
        sb.AppendLine($"Subkeys: {_subkeys.Count}");

        foreach (var subkey in _subkeys)
        {
            var algorithm = subkey.Algorithm == PgpAlgorithm.Ed25519 ? "Ed25519" : "Curve25519";
            var usage = subkey.Usage switch
            {
                KeyUsage.Sign => "Signing",
                KeyUsage.Authenticate => "Authentication",
                KeyUsage.EncryptCommunications | KeyUsage.EncryptStorage => "Encryption",
                _ => "Unknown"
            };
            
            sb.AppendLine($"  - {algorithm} ({usage}) {Convert.ToHexString(subkey.KeyId).ToLowerInvariant()}");
        }

        return sb.ToString();
    }

    /// <summary>
    /// Creates ASCII armor around binary data.
    /// </summary>
    /// <param name="armorType">The armor type string.</param>
    /// <param name="data">The binary data to armor.</param>
    /// <returns>The ASCII armored data.</returns>
    private static string ArmorData(string armorType, byte[] data)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"-----BEGIN {armorType}-----");
        sb.AppendLine();
        
        // Convert to base64 and format in 64-character lines
        var base64 = Convert.ToBase64String(data);
        for (int i = 0; i < base64.Length; i += 64)
        {
            var lineLength = Math.Min(64, base64.Length - i);
            sb.AppendLine(base64.Substring(i, lineLength));
        }
        
        // Calculate CRC24 checksum
        var crc24 = CalculateCrc24(data);
        var crcBytes = new byte[] {
            (byte)((crc24 >> 16) & 0xFF),
            (byte)((crc24 >> 8) & 0xFF),
            (byte)(crc24 & 0xFF)
        };
        
        sb.AppendLine($"={Convert.ToBase64String(crcBytes)}");
        sb.AppendLine($"-----END {armorType}-----");
        
        return sb.ToString();
    }

    /// <summary>
    /// Calculates the CRC24 checksum used in ASCII armor.
    /// </summary>
    /// <param name="data">The data to checksum.</param>
    /// <returns>The CRC24 checksum.</returns>
    private static uint CalculateCrc24(byte[] data)
    {
        const uint CRC24_INIT = 0xB704CE;
        const uint CRC24_POLY = 0x1864CFB;

        uint crc = CRC24_INIT;
        
        foreach (byte b in data)
        {
            crc ^= (uint)(b << 16);
            for (int i = 0; i < 8; i++)
            {
                crc <<= 1;
                if ((crc & 0x1000000) != 0)
                {
                    crc ^= CRC24_POLY;
                }
            }
        }
        
        return crc & 0xFFFFFF;
    }

    /// <summary>
    /// Throws an exception if the key set has been disposed.
    /// </summary>
    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (!_disposed)
        {
            MasterKey?.Dispose();
            
            foreach (var subkey in _subkeys)
            {
                subkey?.Dispose();
            }
            
            _subkeys.Clear();
            _signatures.Clear();
            
            _disposed = true;
        }
    }

    /// <summary>
    /// Returns a string representation of the key set.
    /// </summary>
    /// <returns>A string representation.</returns>
    public override string ToString()
    {
        if (_disposed)
        {
            return "KeySet(disposed)";
        }
        
        var keyIdHex = Convert.ToHexString(KeyId).ToLowerInvariant();
        return $"KeySet(master={keyIdHex[^8..]}, subkeys={_subkeys.Count}, userId={PrimaryUserId})";
    }
}