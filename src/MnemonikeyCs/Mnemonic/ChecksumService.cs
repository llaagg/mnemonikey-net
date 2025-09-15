using System.IO.Hashing;

namespace MnemonikeyCs.Mnemonic;

public static class ChecksumService
{
    public static uint ComputeCrc32(ReadOnlySpan<byte> data)
    {
        return Crc32.HashToUInt32(data);
    }

    public static uint ComputeCrc32(byte[] data)
    {
        return ComputeCrc32(data.AsSpan());
    }

    public static bool VerifyCrc32(ReadOnlySpan<byte> data, uint expectedChecksum)
    {
        var actualChecksum = ComputeCrc32(data);
        return actualChecksum == expectedChecksum;
    }
}