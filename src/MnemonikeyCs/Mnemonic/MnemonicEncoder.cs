using System.Numerics;
using MnemonikeyCs.Core;

namespace MnemonikeyCs.Mnemonic;

public static class MnemonicEncoder
{
    public static string[] EncodeToPlaintext(Seed seed, DateTime creationTime)
    {
        var payload = CreatePlaintextPayload(seed, creationTime);
        return EncodePayload(payload, Constants.PlaintextPhraseBitCount);
    }

    public static string[] EncodeToEncrypted(Seed seed, DateTime creationTime, ReadOnlySpan<byte> password)
    {
        var payload = CreateEncryptedPayload(seed, creationTime, password);
        return EncodePayload(payload, Constants.EncryptedPhraseBitCount);
    }

    private static BigInteger CreatePlaintextPayload(Seed seed, DateTime creationTime)
    {
        var bitBuffer = new BitBuffer();

        // Version (4 bits) - Version 0 for plaintext
        bitBuffer.AppendTrailingBits(0, Constants.MnemonicVersionBitCount);

        // Entropy (128 bits)
        var seedBigInt = seed.ToBigInteger();
        bitBuffer.AppendTrailingBits(seedBigInt, Constants.EntropyBitCount);

        // Creation offset (31 bits)
        var creationOffset = GetCreationOffset(creationTime);
        bitBuffer.AppendTrailingBits(creationOffset, Constants.CreationOffsetBitCount);

        // Calculate checksum (5 bits)
        var payloadBytes = bitBuffer.ToByteArray();
        var checksum = ChecksumService.ComputeCrc32(payloadBytes) & Constants.ChecksumMask;
        bitBuffer.AppendTrailingBits(checksum, Constants.ChecksumBitCount);

        return bitBuffer.ToBigInteger();
    }

    private static BigInteger CreateEncryptedPayload(Seed seed, DateTime creationTime, ReadOnlySpan<byte> password)
    {
        var bitBuffer = new BitBuffer();

        // Generate salt (19 bits)
        var salt = GenerateSalt();

        // Encrypt entropy using Argon2
        var encryptionKey = DeriveEncryptionKey(password, salt, creationTime);
        var encryptedSeed = EncryptSeed(seed, encryptionKey);

        // Version (4 bits) - Version 1 for encrypted
        bitBuffer.AppendTrailingBits(1, Constants.MnemonicVersionBitCount);

        // Encrypted entropy (128 bits)
        var encryptedSeedBigInt = new BigInteger(encryptedSeed, isUnsigned: true, isBigEndian: true);
        bitBuffer.AppendTrailingBits(encryptedSeedBigInt, Constants.EntropyBitCount);

        // Salt (19 bits)
        bitBuffer.AppendTrailingBits(salt, Constants.SaltBitCount);

        // Encryption seed verify (5 bits)
        var verify = encryptionKey[16] & Constants.EncSeedVerifyMask;
        bitBuffer.AppendTrailingBits(verify, Constants.EncSeedVerifyBitCount);

        // Creation offset (31 bits)
        var creationOffset = GetCreationOffset(creationTime);
        bitBuffer.AppendTrailingBits(creationOffset, Constants.CreationOffsetBitCount);

        // Calculate checksum (5 bits)
        var payloadBytes = bitBuffer.ToByteArray();
        var checksum = ChecksumService.ComputeCrc32(payloadBytes) & Constants.ChecksumMask;
        bitBuffer.AppendTrailingBits(checksum, Constants.ChecksumBitCount);

        return bitBuffer.ToBigInteger();
    }

    private static string[] EncodePayload(BigInteger payload, uint bitCount)
    {
        var indices = EncodeToIndices(payload, bitCount);
        var words = new string[indices.Length];
        
        for (int i = 0; i < indices.Length; i++)
        {
            words[i] = Wordlist4096.GetWord(indices[i]);
        }
        
        return words;
    }

    private static ushort[] EncodeToIndices(BigInteger payload, uint bitCount)
    {
        if (bitCount % Wordlist4096.BitsPerWord != 0)
        {
            throw new ArgumentException($"Bit count must be divisible by {Wordlist4096.BitsPerWord}", nameof(bitCount));
        }

        var wordCount = (int)(bitCount / Wordlist4096.BitsPerWord);
        var indices = new ushort[wordCount];
        var remainingPayload = payload;

        // Extract words from right to left (least significant bits first)
        for (int i = wordCount - 1; i >= 0; i--)
        {
            var wordIndex = remainingPayload & ((1 << Wordlist4096.BitsPerWord) - 1);
            indices[i] = (ushort)wordIndex;
            remainingPayload >>= Wordlist4096.BitsPerWord;
        }

        return indices;
    }

    private static uint GetCreationOffset(DateTime creationTime)
    {
        var epoch = new DateTime(2023, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        var offset = (long)(creationTime - epoch).TotalSeconds;
        
        if (offset < 0)
        {
            throw new ArgumentException("Creation time cannot be before 2023-01-01", nameof(creationTime));
        }
        
        if (offset > (1L << (int)Constants.CreationOffsetBitCount) - 1)
        {
            throw new ArgumentException("Creation time is too far in the future", nameof(creationTime));
        }

        return (uint)offset;
    }

    private static uint GenerateSalt()
    {
        using var rng = System.Security.Cryptography.RandomNumberGenerator.Create();
        var saltBytes = new byte[4];
        rng.GetBytes(saltBytes);
        var salt = BitConverter.ToUInt32(saltBytes, 0);
        return salt & Constants.SaltMask;
    }

    private static byte[] DeriveEncryptionKey(ReadOnlySpan<byte> password, uint salt, DateTime creationTime)
    {
        // Combine salt with creation offset
        var creationOffset = GetCreationOffset(creationTime);
        var saltBytes = BitConverter.GetBytes(salt);
        var offsetBytes = BitConverter.GetBytes(creationOffset);
        
        var combinedSalt = new byte[saltBytes.Length + offsetBytes.Length];
        saltBytes.CopyTo(combinedSalt, 0);
        offsetBytes.CopyTo(combinedSalt, saltBytes.Length);

        return Crypto.Argon2Service.DeriveKeyForEncryption(password, combinedSalt);
    }

    private static byte[] EncryptSeed(Seed seed, byte[] encryptionKey)
    {
        // Use AES-128 to encrypt the seed
        using var aes = System.Security.Cryptography.Aes.Create();
        aes.Key = encryptionKey[..16]; // Use first 16 bytes as AES key
        aes.Mode = System.Security.Cryptography.CipherMode.ECB;
        aes.Padding = System.Security.Cryptography.PaddingMode.None;

        using var encryptor = aes.CreateEncryptor();
        return encryptor.TransformFinalBlock(seed.ToBytes(), 0, 16);
    }
}