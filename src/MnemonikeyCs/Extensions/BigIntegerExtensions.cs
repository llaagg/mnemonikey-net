using System.Numerics;

namespace MnemonikeyCs.Extensions;

/// <summary>
/// Extension methods for BigInteger operations.
/// </summary>
public static class BigIntegerExtensions
{
    /// <summary>
    /// Gets the number of bits required to represent this BigInteger.
    /// </summary>
    /// <param name="value">The BigInteger value.</param>
    /// <returns>The number of bits required.</returns>
    public static int GetBitLength(this BigInteger value)
    {
        if (value.IsZero)
            return 0;
        
        if (value < 0)
            value = -value;
        
        var bytes = value.ToByteArray();
        var bitLength = (bytes.Length - 1) * 8;
        var lastByte = bytes[^1];
        
        while (lastByte != 0)
        {
            bitLength++;
            lastByte >>= 1;
        }
        
        return bitLength;
    }

    /// <summary>
    /// Extracts the specified number of least significant bits from the BigInteger.
    /// </summary>
    /// <param name="value">The BigInteger value.</param>
    /// <param name="bitCount">The number of bits to extract.</param>
    /// <returns>A BigInteger containing only the extracted bits.</returns>
    public static BigInteger ExtractBits(this BigInteger value, int bitCount)
    {
        if (bitCount <= 0)
            return BigInteger.Zero;
        
        // Use consistent masking approach for all bit counts to avoid overflow
        var mask = (BigInteger.One << bitCount) - 1;
        return value & mask;
    }

    /// <summary>
    /// Right-shifts the BigInteger by the specified number of bits in place.
    /// </summary>
    /// <param name="value">The BigInteger value to shift.</param>
    /// <param name="bitCount">The number of bits to shift right.</param>
    /// <returns>The shifted BigInteger.</returns>
    public static BigInteger RightShift(this BigInteger value, int bitCount)
    {
        return value >> bitCount;
    }

    /// <summary>
    /// Left-shifts the BigInteger by the specified number of bits.
    /// </summary>
    /// <param name="value">The BigInteger value to shift.</param>
    /// <param name="bitCount">The number of bits to shift left.</param>
    /// <returns>The shifted BigInteger.</returns>
    public static BigInteger LeftShift(this BigInteger value, int bitCount)
    {
        return value << bitCount;
    }

    /// <summary>
    /// Converts the BigInteger to a byte array with specified endianness and size.
    /// </summary>
    /// <param name="value">The BigInteger value.</param>
    /// <param name="isUnsigned">Whether to treat the value as unsigned.</param>
    /// <param name="isBigEndian">Whether to use big-endian byte order.</param>
    /// <param name="byteCount">The desired byte array size (pads with zeros if necessary).</param>
    /// <returns>The byte array representation.</returns>
    public static byte[] ToByteArray(this BigInteger value, bool isUnsigned, bool isBigEndian, int? byteCount = null)
    {
        var bytes = value.ToByteArray(isUnsigned, isBigEndian);
        
        if (byteCount.HasValue && bytes.Length != byteCount.Value)
        {
            var result = new byte[byteCount.Value];
            if (bytes.Length < byteCount.Value)
            {
                // Pad with zeros
                var offset = isBigEndian ? byteCount.Value - bytes.Length : 0;
                bytes.CopyTo(result, offset);
            }
            else
            {
                // Truncate (take least significant bytes)
                var offset = isBigEndian ? bytes.Length - byteCount.Value : 0;
                Array.Copy(bytes, offset, result, 0, byteCount.Value);
            }
            return result;
        }
        
        return bytes;
    }
}