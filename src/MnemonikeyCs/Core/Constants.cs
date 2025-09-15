using System;

namespace MnemonikeyCs.Core;

/// <summary>
/// Global constants used throughout the mnemonikey implementation.
/// These values must match the original Go implementation exactly.
/// </summary>
public static class Constants
{
    /// <summary>
    /// The Mnemonikey epoch start time: midnight UTC on 2023-01-01.
    /// This corresponds to Unix timestamp 1672531200.
    /// </summary>
    public static readonly DateTime EpochStart = new DateTime(2023, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    /// <summary>
    /// The increment between valid key creation times (1 second).
    /// </summary>
    public static readonly TimeSpan EpochIncrement = TimeSpan.FromSeconds(1);

    /// <summary>
    /// Maximum creation time that can be encoded in the creation offset.
    /// </summary>
    public static readonly DateTime MaxCreationTime = EpochStart.AddSeconds((1L << CreationOffsetBitCount) - 1);

    /// <summary>
    /// Number of bits used to encode the creation offset.
    /// </summary>
    public const int CreationOffsetBitCount = 31;

    /// <summary>
    /// Number of bits of entropy in the seed.
    /// </summary>
    public const int EntropyBitCount = 128;

    /// <summary>
    /// Number of bits used for the mnemonic version.
    /// </summary>
    public const int MnemonicVersionBitCount = 4;

    /// <summary>
    /// Number of bits used for the checksum.
    /// </summary>
    public const int ChecksumBitCount = 5;

    /// <summary>
    /// Mask for extracting checksum bits.
    /// </summary>
    public const uint ChecksumMask = (1u << ChecksumBitCount) - 1;

    /// <summary>
    /// Number of bits used for the salt in encrypted phrases.
    /// </summary>
    public const int SaltBitCount = 19;

    /// <summary>
    /// Number of bits used for encrypted seed verification.
    /// </summary>
    public const int EncSeedVerifyBitCount = 5;

    /// <summary>
    /// Mask for extracting encrypted seed verification bits.
    /// </summary>
    public const uint EncSeedVerifyMask = (1u << EncSeedVerifyBitCount) - 1;

    /// <summary>
    /// Mask for extracting salt bits.
    /// </summary>
    public const uint SaltMask = (1u << SaltBitCount) - 1;

    /// <summary>
    /// Number of bits per word in the mnemonic wordlist.
    /// </summary>
    public const int BitsPerWord = 12;

    /// <summary>
    /// Size of the wordlist (2^12 = 4096 words).
    /// </summary>
    public const int WordlistSize = 1 << BitsPerWord;

    /// <summary>
    /// Argon2id time parameter (iterations).
    /// </summary>
    public const uint ArgonTimeFactor = 4;

    /// <summary>
    /// Argon2id memory parameter (512MB).
    /// </summary>
    public const uint ArgonMemoryFactor = 0x80000;

    /// <summary>
    /// Argon2id parallelism parameter.
    /// </summary>
    public const uint ArgonThreads = 2;

    /// <summary>
    /// Size of the root key derived from Argon2id.
    /// </summary>
    public const int RootKeySize = 32;

    /// <summary>
    /// Size of Ed25519 private keys.
    /// </summary>
    public const int Ed25519PrivateKeySize = 32;

    /// <summary>
    /// Size of Ed25519 public keys.
    /// </summary>
    public const int Ed25519PublicKeySize = 32;

    /// <summary>
    /// Size of Curve25519 private keys.
    /// </summary>
    public const int Curve25519PrivateKeySize = 32;

    /// <summary>
    /// Size of Curve25519 public keys.
    /// </summary>
    public const int Curve25519PublicKeySize = 32;

    /// <summary>
    /// Master key HKDF info string.
    /// </summary>
    public const string KeyExpandInfoMaster = "mnemonikey master key";

    /// <summary>
    /// Subkey HKDF info format string.
    /// </summary>
    public const string KeyExpandInfoSubkeyFormat = "mnemonikey {0} subkey";

    /// <summary>
    /// Total bit count for plaintext phrases (14 words × 12 bits = 168 bits).
    /// Version(4) + Entropy(128) + CreationOffset(31) + Checksum(5) = 168 bits.
    /// </summary>
    public const uint PlaintextPhraseBitCount = 168;

    /// <summary>
    /// Total bit count for encrypted phrases (16 words × 12 bits = 192 bits).
    /// Version(4) + EncryptedEntropy(128) + Salt(19) + EncSeedVerify(5) + CreationOffset(31) + Checksum(5) = 192 bits.
    /// </summary>
    public const uint EncryptedPhraseBitCount = 192;
}