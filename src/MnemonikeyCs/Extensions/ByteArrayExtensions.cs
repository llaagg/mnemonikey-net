using System;
using System.Security.Cryptography;
using System.Text;

namespace MnemonikeyCs.Extensions;

/// <summary>
/// Extension methods for byte arrays.
/// </summary>
public static class ByteArrayExtensions
{
    /// <summary>
    /// Securely clears a byte array by overwriting it with zeros.
    /// </summary>
    /// <param name="bytes">The byte array to clear.</param>
    public static void SecureClear(this byte[] bytes)
    {
        if (bytes != null)
        {
            Array.Clear(bytes, 0, bytes.Length);
        }
    }

    /// <summary>
    /// Securely clears a span of bytes by overwriting it with zeros.
    /// </summary>
    /// <param name="bytes">The span to clear.</param>
    public static void SecureClear(this Span<byte> bytes)
    {
        bytes.Clear();
    }

    /// <summary>
    /// Performs constant-time comparison of two byte arrays to prevent timing attacks.
    /// </summary>
    /// <param name="a">The first byte array.</param>
    /// <param name="b">The second byte array.</param>
    /// <returns>true if the arrays are equal; otherwise, false.</returns>
    public static bool ConstantTimeEquals(this byte[]? a, byte[]? b)
    {
        if (ReferenceEquals(a, b))
            return true;
        
        if (a is null || b is null)
            return false;
        
        if (a.Length != b.Length)
            return false;

        return CryptographicOperations.FixedTimeEquals(a, b);
    }

    /// <summary>
    /// Performs constant-time comparison of two spans to prevent timing attacks.
    /// </summary>
    /// <param name="a">The first span.</param>
    /// <param name="b">The second span.</param>
    /// <returns>true if the spans are equal; otherwise, false.</returns>
    public static bool ConstantTimeEquals(this ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        return CryptographicOperations.FixedTimeEquals(a, b);
    }

    /// <summary>
    /// Converts a byte array to a hexadecimal string.
    /// </summary>
    /// <param name="bytes">The byte array to convert.</param>
    /// <param name="lowercase">Whether to use lowercase hex characters.</param>
    /// <returns>The hexadecimal string representation.</returns>
    public static string ToHexString(this byte[] bytes, bool lowercase = true)
    {
        if (bytes == null || bytes.Length == 0)
            return string.Empty;

        var hex = Convert.ToHexString(bytes);
        return lowercase ? hex.ToLowerInvariant() : hex;
    }

    /// <summary>
    /// Converts a byte array to a hexadecimal string with optional prefix.
    /// </summary>
    /// <param name="bytes">The byte array to convert.</param>
    /// <param name="prefix">The prefix to add (e.g., "0x").</param>
    /// <param name="lowercase">Whether to use lowercase hex characters.</param>
    /// <returns>The hexadecimal string representation with prefix.</returns>
    public static string ToHexString(this byte[] bytes, string prefix, bool lowercase = true)
    {
        var hex = ToHexString(bytes, lowercase);
        return string.IsNullOrEmpty(hex) ? hex : prefix + hex;
    }

    /// <summary>
    /// Reverses the byte order of an array in place.
    /// </summary>
    /// <param name="bytes">The byte array to reverse.</param>
    /// <returns>The same array instance (for fluent chaining).</returns>
    public static byte[] ReverseInPlace(this byte[] bytes)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        Array.Reverse(bytes);
        return bytes;
    }

    /// <summary>
    /// Creates a reversed copy of a byte array.
    /// </summary>
    /// <param name="bytes">The byte array to reverse.</param>
    /// <returns>A new reversed byte array.</returns>
    public static byte[]? ReverseCopy(this byte[]? bytes)
    {
        if (bytes == null)
            return null;

        var reversed = new byte[bytes.Length];
        for (int i = 0; i < bytes.Length; i++)
        {
            reversed[i] = bytes[bytes.Length - 1 - i];
        }
        return reversed;
    }

    /// <summary>
    /// Converts a byte array to a Base64 string.
    /// </summary>
    /// <param name="bytes">The byte array to convert.</param>
    /// <returns>The Base64 string representation.</returns>
    public static string ToBase64String(this byte[] bytes)
    {
        return bytes == null ? string.Empty : Convert.ToBase64String(bytes);
    }

    /// <summary>
    /// XORs two byte arrays together.
    /// </summary>
    /// <param name="a">The first byte array.</param>
    /// <param name="b">The second byte array.</param>
    /// <returns>A new byte array containing the XOR result.</returns>
    /// <exception cref="ArgumentException">Thrown when arrays have different lengths.</exception>
    public static byte[] Xor(this byte[] a, byte[] b)
    {
        ArgumentNullException.ThrowIfNull(a);
        ArgumentNullException.ThrowIfNull(b);
        
        if (a.Length != b.Length)
            throw new ArgumentException("Arrays must have the same length");

        var result = new byte[a.Length];
        for (int i = 0; i < a.Length; i++)
        {
            result[i] = (byte)(a[i] ^ b[i]);
        }
        return result;
    }

    /// <summary>
    /// XORs two byte arrays together in place, modifying the first array.
    /// </summary>
    /// <param name="a">The byte array to modify.</param>
    /// <param name="b">The byte array to XOR with.</param>
    /// <returns>The modified first array (for fluent chaining).</returns>
    public static byte[] XorInPlace(this byte[] a, byte[] b)
    {
        ArgumentNullException.ThrowIfNull(a);
        ArgumentNullException.ThrowIfNull(b);
        
        if (a.Length != b.Length)
            throw new ArgumentException("Arrays must have the same length");

        for (int i = 0; i < a.Length; i++)
        {
            a[i] ^= b[i];
        }
        return a;
    }

    /// <summary>
    /// Concatenates multiple byte arrays into a single array.
    /// </summary>
    /// <param name="first">The first byte array.</param>
    /// <param name="others">Additional byte arrays to concatenate.</param>
    /// <returns>A new byte array containing all concatenated data.</returns>
    public static byte[] Concat(this byte[] first, params byte[][] others)
    {
        ArgumentNullException.ThrowIfNull(first);
        ArgumentNullException.ThrowIfNull(others);

        var totalLength = first.Length;
        foreach (var array in others)
        {
            if (array != null)
                totalLength += array.Length;
        }

        var result = new byte[totalLength];
        var offset = 0;
        
        first.CopyTo(result, offset);
        offset += first.Length;
        
        foreach (var array in others)
        {
            if (array != null)
            {
                array.CopyTo(result, offset);
                offset += array.Length;
            }
        }

        return result;
    }

    /// <summary>
    /// Extracts a sub-array from a byte array.
    /// </summary>
    /// <param name="source">The source byte array.</param>
    /// <param name="start">The starting index.</param>
    /// <param name="length">The length of the sub-array.</param>
    /// <returns>A new byte array containing the extracted data.</returns>
    public static byte[] SubArray(this byte[] source, int start, int length)
    {
        ArgumentNullException.ThrowIfNull(source);
        
        if (start < 0 || start >= source.Length)
            throw new ArgumentOutOfRangeException(nameof(start));
        
        if (length < 0 || start + length > source.Length)
            throw new ArgumentOutOfRangeException(nameof(length));

        var result = new byte[length];
        Array.Copy(source, start, result, 0, length);
        return result;
    }

    /// <summary>
    /// Checks if a byte array starts with another byte array.
    /// </summary>
    /// <param name="source">The source byte array.</param>
    /// <param name="prefix">The prefix to check for.</param>
    /// <returns>true if the source starts with the prefix; otherwise, false.</returns>
    public static bool StartsWith(this byte[] source, byte[] prefix)
    {
        if (source == null || prefix == null)
            return false;
        
        if (prefix.Length > source.Length)
            return false;

        return source.AsSpan(0, prefix.Length).SequenceEqual(prefix);
    }

    /// <summary>
    /// Pads a byte array to a specific length with zeros at the beginning.
    /// </summary>
    /// <param name="source">The source byte array.</param>
    /// <param name="totalLength">The desired total length.</param>
    /// <returns>A new byte array padded to the specified length.</returns>
    public static byte[] PadLeft(this byte[] source, int totalLength)
    {
        ArgumentNullException.ThrowIfNull(source);
        
        if (totalLength < source.Length)
            throw new ArgumentException("Total length must be greater than or equal to source length");

        if (totalLength == source.Length)
            return (byte[])source.Clone();

        var result = new byte[totalLength];
        source.CopyTo(result, totalLength - source.Length);
        return result;
    }

    /// <summary>
    /// Computes the SHA256 hash of a byte array.
    /// </summary>
    /// <param name="data">The data to hash.</param>
    /// <returns>The SHA256 hash.</returns>
    public static byte[] Sha256(this byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        
        using var sha256 = SHA256.Create();
        return sha256.ComputeHash(data);
    }
}