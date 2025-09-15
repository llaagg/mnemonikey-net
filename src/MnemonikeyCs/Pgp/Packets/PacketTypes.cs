using System;

namespace MnemonikeyCs.Pgp.Packets;

/// <summary>
/// OpenPGP packet types as defined in RFC 4880.
/// </summary>
public enum PacketType : byte
{
    /// <summary>
    /// Reserved - a packet tag must not have this value.
    /// </summary>
    Reserved = 0,

    /// <summary>
    /// Public-Key Encrypted Session Key Packet.
    /// </summary>
    PublicKeyEncryptedSessionKey = 1,

    /// <summary>
    /// Signature Packet.
    /// </summary>
    Signature = 2,

    /// <summary>
    /// Symmetric-Key Encrypted Session Key Packet.
    /// </summary>
    SymmetricKeyEncryptedSessionKey = 3,

    /// <summary>
    /// One-Pass Signature Packet.
    /// </summary>
    OnePassSignature = 4,

    /// <summary>
    /// Secret-Key Packet.
    /// </summary>
    SecretKey = 5,

    /// <summary>
    /// Public-Key Packet.
    /// </summary>
    PublicKey = 6,

    /// <summary>
    /// Secret-Subkey Packet.
    /// </summary>
    SecretSubkey = 7,

    /// <summary>
    /// Compressed Data Packet.
    /// </summary>
    CompressedData = 8,

    /// <summary>
    /// Symmetrically Encrypted Data Packet.
    /// </summary>
    SymmetricallyEncryptedData = 9,

    /// <summary>
    /// Marker Packet.
    /// </summary>
    Marker = 10,

    /// <summary>
    /// Literal Data Packet.
    /// </summary>
    LiteralData = 11,

    /// <summary>
    /// Trust Packet.
    /// </summary>
    Trust = 12,

    /// <summary>
    /// User ID Packet.
    /// </summary>
    UserId = 13,

    /// <summary>
    /// Public-Subkey Packet.
    /// </summary>
    PublicSubkey = 14,

    /// <summary>
    /// User Attribute Packet.
    /// </summary>
    UserAttribute = 17,

    /// <summary>
    /// Sym. Encrypted and Integrity Protected Data Packet.
    /// </summary>
    SymmetricallyEncryptedIntegrityProtectedData = 18,

    /// <summary>
    /// Modification Detection Code Packet.
    /// </summary>
    ModificationDetectionCode = 19
}

/// <summary>
/// Signature types as defined in RFC 4880.
/// </summary>
public enum SignatureType : byte
{
    /// <summary>
    /// Signature of a binary document.
    /// </summary>
    BinaryDocument = 0x00,

    /// <summary>
    /// Signature of a canonical text document.
    /// </summary>
    CanonicalTextDocument = 0x01,

    /// <summary>
    /// Standalone signature.
    /// </summary>
    Standalone = 0x02,

    /// <summary>
    /// Generic certification of a User ID and Public-Key packet.
    /// </summary>
    GenericCertification = 0x10,

    /// <summary>
    /// Persona certification of a User ID and Public-Key packet.
    /// </summary>
    PersonaCertification = 0x11,

    /// <summary>
    /// Casual certification of a User ID and Public-Key packet.
    /// </summary>
    CasualCertification = 0x12,

    /// <summary>
    /// Positive certification of a User ID and Public-Key packet.
    /// </summary>
    PositiveCertification = 0x13,

    /// <summary>
    /// Subkey Binding Signature.
    /// </summary>
    SubkeyBinding = 0x18,

    /// <summary>
    /// Primary Key Binding Signature.
    /// </summary>
    PrimaryKeyBinding = 0x19,

    /// <summary>
    /// Signature directly on a key.
    /// </summary>
    DirectlyOnKey = 0x1F,

    /// <summary>
    /// Key revocation signature.
    /// </summary>
    KeyRevocation = 0x20,

    /// <summary>
    /// Subkey revocation signature.
    /// </summary>
    SubkeyRevocation = 0x28,

    /// <summary>
    /// Certification revocation signature.
    /// </summary>
    CertificationRevocation = 0x30,

    /// <summary>
    /// Timestamp signature.
    /// </summary>
    Timestamp = 0x40
}

/// <summary>
/// Hash algorithms as defined in RFC 4880.
/// </summary>
public enum HashAlgorithm : byte
{
    /// <summary>
    /// MD5.
    /// </summary>
    MD5 = 1,

    /// <summary>
    /// SHA-1.
    /// </summary>
    SHA1 = 2,

    /// <summary>
    /// RIPE-MD/160.
    /// </summary>
    RIPEMD160 = 3,

    /// <summary>
    /// SHA-256.
    /// </summary>
    SHA256 = 8,

    /// <summary>
    /// SHA-384.
    /// </summary>
    SHA384 = 9,

    /// <summary>
    /// SHA-512.
    /// </summary>
    SHA512 = 10,

    /// <summary>
    /// SHA-224.
    /// </summary>
    SHA224 = 11
}

/// <summary>
/// Symmetric key algorithms as defined in RFC 4880.
/// </summary>
public enum SymmetricAlgorithm : byte
{
    /// <summary>
    /// Plaintext or unencrypted data.
    /// </summary>
    Plaintext = 0,

    /// <summary>
    /// IDEA.
    /// </summary>
    IDEA = 1,

    /// <summary>
    /// TripleDES (DES-EDE, 168 bit key derived from 192).
    /// </summary>
    TripleDES = 2,

    /// <summary>
    /// CAST5 (128 bit key, as per RFC 2144).
    /// </summary>
    CAST5 = 3,

    /// <summary>
    /// Blowfish (128 bit key, 16 rounds).
    /// </summary>
    Blowfish = 4,

    /// <summary>
    /// AES with 128-bit key.
    /// </summary>
    AES128 = 7,

    /// <summary>
    /// AES with 192-bit key.
    /// </summary>
    AES192 = 8,

    /// <summary>
    /// AES with 256-bit key.
    /// </summary>
    AES256 = 9,

    /// <summary>
    /// Twofish with 256-bit key.
    /// </summary>
    Twofish = 10
}

/// <summary>
/// Compression algorithms as defined in RFC 4880.
/// </summary>
public enum CompressionAlgorithm : byte
{
    /// <summary>
    /// Uncompressed.
    /// </summary>
    Uncompressed = 0,

    /// <summary>
    /// ZIP (RFC 1951).
    /// </summary>
    ZIP = 1,

    /// <summary>
    /// ZLIB (RFC 1950).
    /// </summary>
    ZLIB = 2,

    /// <summary>
    /// BZip2.
    /// </summary>
    BZip2 = 3
}

/// <summary>
/// String-to-Key (S2K) types as defined in RFC 4880.
/// </summary>
public enum S2KType : byte
{
    /// <summary>
    /// Simple S2K.
    /// </summary>
    Simple = 0,

    /// <summary>
    /// Salted S2K.
    /// </summary>
    Salted = 1,

    /// <summary>
    /// Iterated and Salted S2K.
    /// </summary>
    IteratedAndSalted = 3
}

/// <summary>
/// Signature subpacket types as defined in RFC 4880.
/// </summary>
public enum SignatureSubpacketType : byte
{
    /// <summary>
    /// Signature creation time.
    /// </summary>
    SignatureCreationTime = 2,

    /// <summary>
    /// Signature expiration time.
    /// </summary>
    SignatureExpirationTime = 3,

    /// <summary>
    /// Exportable certification.
    /// </summary>
    ExportableCertification = 4,

    /// <summary>
    /// Trust signature.
    /// </summary>
    TrustSignature = 5,

    /// <summary>
    /// Regular expression.
    /// </summary>
    RegularExpression = 6,

    /// <summary>
    /// Revocable.
    /// </summary>
    Revocable = 7,

    /// <summary>
    /// Key expiration time.
    /// </summary>
    KeyExpirationTime = 9,

    /// <summary>
    /// Preferred symmetric algorithms.
    /// </summary>
    PreferredSymmetricAlgorithms = 11,

    /// <summary>
    /// Revocation key.
    /// </summary>
    RevocationKey = 12,

    /// <summary>
    /// Issuer.
    /// </summary>
    Issuer = 16,

    /// <summary>
    /// Notation data.
    /// </summary>
    NotationData = 20,

    /// <summary>
    /// Preferred hash algorithms.
    /// </summary>
    PreferredHashAlgorithms = 21,

    /// <summary>
    /// Preferred compression algorithms.
    /// </summary>
    PreferredCompressionAlgorithms = 22,

    /// <summary>
    /// Key server preferences.
    /// </summary>
    KeyServerPreferences = 23,

    /// <summary>
    /// Preferred key server.
    /// </summary>
    PreferredKeyServer = 24,

    /// <summary>
    /// Primary user ID.
    /// </summary>
    PrimaryUserId = 25,

    /// <summary>
    /// Policy URI.
    /// </summary>
    PolicyURI = 26,

    /// <summary>
    /// Key flags.
    /// </summary>
    KeyFlags = 27,

    /// <summary>
    /// Signer's user ID.
    /// </summary>
    SignersUserId = 28,

    /// <summary>
    /// Reason for revocation.
    /// </summary>
    ReasonForRevocation = 29,

    /// <summary>
    /// Features.
    /// </summary>
    Features = 30,

    /// <summary>
    /// Signature target.
    /// </summary>
    SignatureTarget = 31,

    /// <summary>
    /// Embedded signature.
    /// </summary>
    EmbeddedSignature = 32
}