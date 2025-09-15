using System;
using System.Numerics;
using MnemonikeyCs.Extensions;

namespace MnemonikeyCs.Core;

/// <summary>
/// A buffer for manipulating bit-level data, compatible with the Go implementation.
/// </summary>
public sealed class BitBuffer
{
    private BigInteger _data;
    private int _bitLength;

    /// <summary>
    /// Initializes a new instance of the BitBuffer class.
    /// </summary>
    public BitBuffer()
    {
        _data = BigInteger.Zero;
        _bitLength = 0;
    }

    /// <summary>
    /// Initializes a new instance of the BitBuffer class with initial data.
    /// </summary>
    /// <param name="initialValue">The initial value.</param>
    /// <param name="bitCount">The number of bits in the initial value.</param>
    public BitBuffer(BigInteger initialValue, int bitCount)
    {
        if (bitCount < 0)
            throw new ArgumentOutOfRangeException(nameof(bitCount), "Bit count cannot be negative");
        
        if (initialValue < 0)
            throw new ArgumentOutOfRangeException(nameof(initialValue), "Value cannot be negative");
        
        if (bitCount > 0 && initialValue.GetBitLength() > bitCount)
            throw new ArgumentException("Initial value exceeds specified bit count");

        _data = initialValue;
        _bitLength = bitCount;
    }

    /// <summary>
    /// Initializes a new instance of the BitBuffer class with initial data and automatic bit count.
    /// </summary>
    /// <param name="initialValue">The initial value.</param>
    public BitBuffer(BigInteger initialValue)
    {
        if (initialValue < 0)
            throw new ArgumentOutOfRangeException(nameof(initialValue), "Value cannot be negative");

        _data = initialValue;
        _bitLength = initialValue == 0 ? 0 : (int)initialValue.GetBitLength();
    }

    /// <summary>
    /// Gets the current number of bits in the buffer.
    /// </summary>
    public int BitLength => _bitLength;

    /// <summary>
    /// Gets the current data as a BigInteger.
    /// </summary>
    public BigInteger Data => _data;

    /// <summary>
    /// Appends bits to the buffer as trailing (least significant) bits.
    /// </summary>
    /// <param name="value">The value to append.</param>
    /// <param name="bitCount">The number of bits to append from the value.</param>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when bitCount is negative.</exception>
    public void AppendTrailingBits(BigInteger value, int bitCount)
    {
        if (bitCount < 0)
            throw new ArgumentOutOfRangeException(nameof(bitCount), "Bit count cannot be negative");
        
        if (bitCount == 0)
            return;

        if (value < 0)
            throw new ArgumentOutOfRangeException(nameof(value), "Value cannot be negative");

        // Extract only the specified number of bits from the value
        var maskedValue = value.ExtractBits(bitCount);
        
        // Shift existing data left and add the new bits
        _data = (_data << bitCount) | maskedValue;
        _bitLength += bitCount;
    }

    /// <summary>
    /// Appends bits to the buffer as leading (most significant) bits.
    /// </summary>
    /// <param name="value">The value to append.</param>
    /// <param name="bitCount">The number of bits to append from the value.</param>
    public void AppendLeadingBits(BigInteger value, int bitCount)
    {
        if (bitCount < 0)
            throw new ArgumentOutOfRangeException(nameof(bitCount), "Bit count cannot be negative");
        
        if (bitCount == 0)
            return;

        if (value < 0)
            throw new ArgumentOutOfRangeException(nameof(value), "Value cannot be negative");

        // Extract only the specified number of bits from the value
        var maskedValue = value.ExtractBits(bitCount);
        
        // Add new bits shifted left, then add existing data
        _data = (maskedValue << _bitLength) | _data;
        _bitLength += bitCount;
    }

    /// <summary>
    /// Extracts and removes the specified number of trailing (least significant) bits.
    /// </summary>
    /// <param name="bitCount">The number of bits to extract.</param>
    /// <returns>The extracted bits as a BigInteger.</returns>
    public BigInteger ExtractTrailingBits(int bitCount)
    {
        if (bitCount < 0)
            throw new ArgumentOutOfRangeException(nameof(bitCount), "Bit count cannot be negative");
        
        if (bitCount > _bitLength)
            throw new ArgumentException("Cannot extract more bits than available", nameof(bitCount));

        if (bitCount == 0)
            return BigInteger.Zero;

        // Extract the trailing bits
        var extractedBits = _data.ExtractBits(bitCount);
        
        // Remove the extracted bits from the buffer
        _data >>= bitCount;
        _bitLength -= bitCount;
        
        return extractedBits;
    }

    /// <summary>
    /// Extracts and removes the specified number of leading (most significant) bits.
    /// </summary>
    /// <param name="bitCount">The number of bits to extract.</param>
    /// <returns>The extracted bits as a BigInteger.</returns>
    public BigInteger ExtractLeadingBits(int bitCount)
    {
        if (bitCount < 0)
            throw new ArgumentOutOfRangeException(nameof(bitCount), "Bit count cannot be negative");
        
        if (bitCount > _bitLength)
            throw new ArgumentException("Cannot extract more bits than available", nameof(bitCount));

        if (bitCount == 0)
            return BigInteger.Zero;

        // Calculate the position of the leading bits
        var shiftAmount = _bitLength - bitCount;
        
        // Extract the leading bits
        var extractedBits = _data >> shiftAmount;
        
        // Remove the extracted bits from the buffer
        var mask = (BigInteger.One << shiftAmount) - 1;
        _data &= mask;
        _bitLength -= bitCount;
        
        return extractedBits;
    }

    /// <summary>
    /// Peeks at the specified number of trailing bits without removing them.
    /// </summary>
    /// <param name="bitCount">The number of bits to peek at.</param>
    /// <returns>The trailing bits as a BigInteger.</returns>
    public BigInteger PeekTrailingBits(int bitCount)
    {
        if (bitCount < 0)
            throw new ArgumentOutOfRangeException(nameof(bitCount), "Bit count cannot be negative");
        
        if (bitCount > _bitLength)
            throw new ArgumentException("Cannot peek at more bits than available", nameof(bitCount));

        if (bitCount == 0)
            return BigInteger.Zero;

        return _data.ExtractBits(bitCount);
    }

    /// <summary>
    /// Peeks at the specified number of leading bits without removing them.
    /// </summary>
    /// <param name="bitCount">The number of bits to peek at.</param>
    /// <returns>The leading bits as a BigInteger.</returns>
    public BigInteger PeekLeadingBits(int bitCount)
    {
        if (bitCount < 0)
            throw new ArgumentOutOfRangeException(nameof(bitCount), "Bit count cannot be negative");
        
        if (bitCount > _bitLength)
            throw new ArgumentException("Cannot peek at more bits than available", nameof(bitCount));

        if (bitCount == 0)
            return BigInteger.Zero;

        var shiftAmount = _bitLength - bitCount;
        return _data >> shiftAmount;
    }

    /// <summary>
    /// Converts the buffer to a byte array using big-endian encoding.
    /// </summary>
    /// <returns>The byte array representation of the buffer.</returns>
    public byte[] ToBytes()
    {
        if (_bitLength == 0)
            return Array.Empty<byte>();

        // Calculate the number of bytes needed
        var byteCount = (_bitLength + 7) / 8;
        
        return _data.ToByteArray(isUnsigned: true, isBigEndian: true, byteCount);
    }

    /// <summary>
    /// Converts the buffer to a byte array with a specific byte count.
    /// </summary>
    /// <param name="byteCount">The desired number of bytes.</param>
    /// <returns>The byte array representation of the buffer.</returns>
    public byte[] ToBytes(int byteCount)
    {
        if (byteCount < 0)
            throw new ArgumentOutOfRangeException(nameof(byteCount), "Byte count cannot be negative");

        if (byteCount == 0)
            return Array.Empty<byte>();

        return _data.ToByteArray(isUnsigned: true, isBigEndian: true, byteCount);
    }

    /// <summary>
    /// Converts the buffer to a byte array using big-endian encoding. Alias for ToBytes().
    /// </summary>
    /// <returns>The byte array representation of the buffer.</returns>
    public byte[] ToByteArray()
    {
        return ToBytes();
    }

    /// <summary>
    /// Converts the buffer to a BigInteger.
    /// </summary>
    /// <returns>The BigInteger representation of the buffer.</returns>
    public BigInteger ToBigInteger()
    {
        return _data;
    }

    /// <summary>
    /// Creates a BitBuffer from a byte array.
    /// </summary>
    /// <param name="bytes">The byte array to read from.</param>
    /// <param name="bitCount">The number of bits to read (optional, defaults to all bits).</param>
    /// <returns>A new BitBuffer instance.</returns>
    public static BitBuffer FromBytes(byte[] bytes, int? bitCount = null)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        
        var effectiveBitCount = bitCount ?? (bytes.Length * 8);
        
        if (effectiveBitCount < 0)
            throw new ArgumentOutOfRangeException(nameof(bitCount), "Bit count cannot be negative");
        
        if (effectiveBitCount > bytes.Length * 8)
            throw new ArgumentException("Bit count exceeds available bits in byte array");

        var data = new BigInteger(bytes, isUnsigned: true, isBigEndian: true);
        
        // If we're reading fewer bits than available, extract only those bits
        if (effectiveBitCount < bytes.Length * 8)
        {
            data = data.ExtractBits(effectiveBitCount);
        }
        
        return new BitBuffer(data, effectiveBitCount);
    }

    /// <summary>
    /// Clears the buffer, setting it to zero bits.
    /// </summary>
    public void Clear()
    {
        _data = BigInteger.Zero;
        _bitLength = 0;
    }

    /// <summary>
    /// Creates a copy of this BitBuffer.
    /// </summary>
    /// <returns>A new BitBuffer with the same data.</returns>
    public BitBuffer Clone()
    {
        return new BitBuffer(_data, _bitLength);
    }

    /// <summary>
    /// Returns a string representation of the buffer showing bit length and data.
    /// </summary>
    /// <returns>A string representation of the buffer.</returns>
    public override string ToString()
    {
        return $"BitBuffer({_bitLength} bits, 0x{_data:X})";
    }

    /// <summary>
    /// Determines whether this BitBuffer is equal to another BitBuffer.
    /// </summary>
    /// <param name="other">The other BitBuffer to compare.</param>
    /// <returns>true if they are equal; otherwise, false.</returns>
    public bool Equals(BitBuffer? other)
    {
        if (other is null) return false;
        if (ReferenceEquals(this, other)) return true;
        return _bitLength == other._bitLength && _data.Equals(other._data);
    }

    /// <summary>
    /// Determines whether the specified object is equal to this instance.
    /// </summary>
    /// <param name="obj">The object to compare with this instance.</param>
    /// <returns>true if they are equal; otherwise, false.</returns>
    public override bool Equals(object? obj) => obj is BitBuffer other && Equals(other);

    /// <summary>
    /// Returns a hash code for this instance.
    /// </summary>
    /// <returns>A hash code for this instance.</returns>
    public override int GetHashCode() => HashCode.Combine(_data, _bitLength);
}