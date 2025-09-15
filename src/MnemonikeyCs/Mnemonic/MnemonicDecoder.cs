using System.Numerics;
using MnemonikeyCs.Core;

namespace MnemonikeyCs.Mnemonic;

public static class MnemonicDecoder
{
    public static (Seed Seed, DateTime CreationTime) DecodePlaintext(string[] words)
    {
        if (words.Length != Constants.PlaintextPhraseBitCount / Wordlist4096.BitsPerWord)
        {
            throw new ArgumentException($"Plaintext phrases must contain exactly {Constants.PlaintextPhraseBitCount / Wordlist4096.BitsPerWord} words", nameof(words));
        }

        var payload = DecodeWordsToPayload(words, Constants.PlaintextPhraseBitCount);
        return ParsePlaintextPayload(payload);
    }

    public static (Seed Seed, DateTime CreationTime) DecodeEncrypted(string[] words, ReadOnlySpan<byte> password)
    {
        if (words.Length != Constants.EncryptedPhraseBitCount / Wordlist4096.BitsPerWord)
        {
            throw new ArgumentException($"Encrypted phrases must contain exactly {Constants.EncryptedPhraseBitCount / Wordlist4096.BitsPerWord} words", nameof(words));
        }

        var payload = DecodeWordsToPayload(words, Constants.EncryptedPhraseBitCount);
        return ParseEncryptedPayload(payload, password);
    }

    public static MnemonicVersion DetectVersion(string[] words)
    {
        if (words.Length == 0)
        {
            throw new ArgumentException("Words array cannot be empty", nameof(words));
        }

        var firstWordIndex = Wordlist4096.GetWordIndex(words[0]);
        var version = firstWordIndex >> (Wordlist4096.BitsPerWord - Constants.MnemonicVersionBitCount);
        
        return version switch
        {
            0 => MnemonicVersion.Plaintext,
            1 => MnemonicVersion.Encrypted,
            _ => throw new ArgumentException($"Unknown mnemonic version: {version}")
        };
    }

    private static BigInteger DecodeWordsToPayload(string[] words, uint expectedBitCount)
    {
        var indices = new ushort[words.Length];
        for (int i = 0; i < words.Length; i++)
        {
            indices[i] = Wordlist4096.GetWordIndex(words[i]);
        }

        return DecodeIndicesToPayload(indices, expectedBitCount);
    }

    private static BigInteger DecodeIndicesToPayload(ushort[] indices, uint expectedBitCount)
    {
        if (expectedBitCount % Wordlist4096.BitsPerWord != 0)
        {
            throw new ArgumentException($"Bit count must be divisible by {Wordlist4096.BitsPerWord}", nameof(expectedBitCount));
        }

        var expectedWordCount = (int)(expectedBitCount / Wordlist4096.BitsPerWord);
        if (indices.Length != expectedWordCount)
        {
            throw new ArgumentException($"Expected {expectedWordCount} words, got {indices.Length}", nameof(indices));
        }

        // Reconstruct payload from left to right (most significant bits first)
        var payload = BigInteger.Zero;
        foreach (var index in indices)
        {
            payload = (payload << Wordlist4096.BitsPerWord) | index;
        }

        return payload;
    }

    private static (Seed Seed, DateTime CreationTime) ParsePlaintextPayload(BigInteger payload)
    {
        var bitBuffer = new BitBuffer(payload, (int)Constants.PlaintextPhraseBitCount);

        // Extract checksum (5 bits from right)
        var checksum = bitBuffer.ExtractTrailingBits(Constants.ChecksumBitCount);

        // Extract creation offset (31 bits)
        var creationOffset = bitBuffer.ExtractTrailingBits(Constants.CreationOffsetBitCount);

        // Extract entropy (128 bits)
        var entropyBigInt = bitBuffer.ExtractTrailingBits(Constants.EntropyBitCount);

        // Extract version (4 bits)
        var version = bitBuffer.ExtractTrailingBits(Constants.MnemonicVersionBitCount);

        // Verify version
        if (version != 0)
        {
            throw new InvalidOperationException($"Expected plaintext version 0, got {version}");
        }

        // Verify checksum
        var payloadForChecksum = CreatePlaintextPayloadForChecksum(entropyBigInt, (uint)creationOffset);
        var expectedChecksum = ChecksumService.ComputeCrc32(payloadForChecksum) & Constants.ChecksumMask;
        if (checksum != expectedChecksum)
        {
            throw new InvalidDataException($"Checksum mismatch: expected 0x{expectedChecksum:X}, got 0x{checksum:X}");
        }

        // Convert to seed and creation time
        var seed = Seed.FromBigInteger(entropyBigInt);
        var creationTime = Constants.EpochStart.AddSeconds((double)creationOffset);

        return (seed, creationTime);
    }

    private static (Seed Seed, DateTime CreationTime) ParseEncryptedPayload(BigInteger payload, ReadOnlySpan<byte> password)
    {
        var bitBuffer = new BitBuffer(payload, (int)Constants.EncryptedPhraseBitCount);

        // Extract checksum (5 bits from right)
        var checksum = bitBuffer.ExtractTrailingBits(Constants.ChecksumBitCount);

        // Extract creation offset (31 bits)
        var creationOffset = bitBuffer.ExtractTrailingBits(Constants.CreationOffsetBitCount);

        // Extract encrypted seed verify (5 bits)
        var encSeedVerify = bitBuffer.ExtractTrailingBits(Constants.EncSeedVerifyBitCount);

        // Extract salt (19 bits)
        var salt = bitBuffer.ExtractTrailingBits(Constants.SaltBitCount);

        // Extract encrypted entropy (128 bits)
        var encryptedEntropyBigInt = bitBuffer.ExtractTrailingBits(Constants.EntropyBitCount);

        // Extract version (4 bits)
        var version = bitBuffer.ExtractTrailingBits(Constants.MnemonicVersionBitCount);

        // Verify version
        if (version != 1)
        {
            throw new InvalidOperationException($"Expected encrypted version 1, got {version}");
        }

        // Derive decryption key
        var creationTime = Constants.EpochStart.AddSeconds((double)creationOffset);
        var encryptionKey = DeriveEncryptionKey(password, (uint)salt, creationTime);

        // Verify encryption key
        var expectedVerify = encryptionKey[16] & Constants.EncSeedVerifyMask;
        if (encSeedVerify != expectedVerify)
        {
            throw new UnauthorizedAccessException("Invalid password or corrupted encrypted phrase");
        }

        // Decrypt entropy
        var encryptedEntropy = ConvertBigIntegerToBytes(encryptedEntropyBigInt, 16);
        var seed = DecryptSeed(encryptedEntropy, encryptionKey);

        // Verify checksum
        var payloadForChecksum = CreateEncryptedPayloadForChecksum(
            encryptedEntropyBigInt, (uint)salt, (uint)encSeedVerify, (uint)creationOffset);
        var expectedChecksum = ChecksumService.ComputeCrc32(payloadForChecksum) & Constants.ChecksumMask;
        if (checksum != expectedChecksum)
        {
            throw new InvalidDataException($"Checksum mismatch: expected 0x{expectedChecksum:X}, got 0x{checksum:X}");
        }

        return (seed, creationTime);
    }

    private static byte[] CreatePlaintextPayloadForChecksum(BigInteger entropy, uint creationOffset)
    {
        var bitBuffer = new BitBuffer();
        bitBuffer.AppendTrailingBits(0, Constants.MnemonicVersionBitCount); // Version 0
        bitBuffer.AppendTrailingBits(entropy, Constants.EntropyBitCount);
        bitBuffer.AppendTrailingBits(creationOffset, Constants.CreationOffsetBitCount);
        return bitBuffer.ToByteArray();
    }

    private static byte[] CreateEncryptedPayloadForChecksum(
        BigInteger encryptedEntropy, uint salt, uint encSeedVerify, uint creationOffset)
    {
        var bitBuffer = new BitBuffer();
        bitBuffer.AppendTrailingBits(1, Constants.MnemonicVersionBitCount); // Version 1
        bitBuffer.AppendTrailingBits(encryptedEntropy, Constants.EntropyBitCount);
        bitBuffer.AppendTrailingBits(salt, Constants.SaltBitCount);
        bitBuffer.AppendTrailingBits(encSeedVerify, Constants.EncSeedVerifyBitCount);
        bitBuffer.AppendTrailingBits(creationOffset, Constants.CreationOffsetBitCount);
        return bitBuffer.ToByteArray();
    }

    private static byte[] DeriveEncryptionKey(ReadOnlySpan<byte> password, uint salt, DateTime creationTime)
    {
        var creationOffset = (uint)(creationTime - Constants.EpochStart).TotalSeconds;
        var saltBytes = BitConverter.GetBytes(salt);
        var offsetBytes = BitConverter.GetBytes(creationOffset);
        
        var combinedSalt = new byte[saltBytes.Length + offsetBytes.Length];
        saltBytes.CopyTo(combinedSalt, 0);
        offsetBytes.CopyTo(combinedSalt, saltBytes.Length);

        return Crypto.Argon2Service.DeriveKeyForEncryption(password, combinedSalt);
    }

    private static Seed DecryptSeed(byte[] encryptedSeed, byte[] encryptionKey)
    {
        using var aes = System.Security.Cryptography.Aes.Create();
        aes.Key = encryptionKey[..16]; // Use first 16 bytes as AES key
        aes.Mode = System.Security.Cryptography.CipherMode.ECB;
        aes.Padding = System.Security.Cryptography.PaddingMode.None;

        using var decryptor = aes.CreateDecryptor();
        var decryptedBytes = decryptor.TransformFinalBlock(encryptedSeed, 0, 16);
        return new Seed(decryptedBytes);
    }

    private static byte[] ConvertBigIntegerToBytes(BigInteger value, int byteCount)
    {
        var bytes = value.ToByteArray(isUnsigned: true, isBigEndian: true);
        if (bytes.Length == byteCount)
        {
            return bytes;
        }

        var result = new byte[byteCount];
        if (bytes.Length < byteCount)
        {
            // Pad with zeros on the left
            Buffer.BlockCopy(bytes, 0, result, byteCount - bytes.Length, bytes.Length);
        }
        else
        {
            // Truncate from the left
            Buffer.BlockCopy(bytes, bytes.Length - byteCount, result, 0, byteCount);
        }
        
        return result;
    }
}