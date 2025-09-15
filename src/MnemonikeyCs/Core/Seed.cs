using System;
using System.Numerics;
using System.Security.Cryptography;
using MnemonikeyCs.Extensions;

namespace MnemonikeyCs.Core;

/// <summary>
/// Represents a 128-bit cryptographic seed used for deterministic key generation.
/// </summary>
public sealed class Seed : IEquatable<Seed>, IDisposable
{
    private readonly byte[] _bytes;
    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of the Seed class from a byte array.
    /// </summary>
    /// <param name="bytes">The 128-bit seed bytes.</param>
    /// <exception cref="ArgumentNullException">Thrown when bytes is null.</exception>
    /// <exception cref="ArgumentException">Thrown when bytes is not exactly 16 bytes.</exception>
    public Seed(byte[] bytes)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        if (bytes.Length != Constants.EntropyBitCount / 8)
        {
            throw new ArgumentException($"Seed must be exactly {Constants.EntropyBitCount / 8} bytes", nameof(bytes));
        }

        _bytes = new byte[bytes.Length];
        bytes.CopyTo(_bytes, 0);
    }

    /// <summary>
    /// Initializes a new instance of the Seed class from a BigInteger.
    /// </summary>
    /// <param name="value">The seed value as a BigInteger.</param>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when value is negative or too large.</exception>
    public Seed(BigInteger value)
    {
        if (value < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(value), "Seed value cannot be negative");
        }

        if (value.GetBitLength() > Constants.EntropyBitCount)
        {
            throw new ArgumentOutOfRangeException(nameof(value), $"Seed value cannot exceed {Constants.EntropyBitCount} bits");
        }

        _bytes = value.ToByteArray(isUnsigned: true, isBigEndian: true);
        
        // Ensure exactly 16 bytes
        if (_bytes.Length < 16)
        {
            var paddedBytes = new byte[16];
            _bytes.CopyTo(paddedBytes, 16 - _bytes.Length);
            _bytes = paddedBytes;
        }
    }

    /// <summary>
    /// Gets the era associated with this seed (currently always 0).
    /// </summary>
    public Era Era => Era.Current;

    /// <summary>
    /// Generates a new random seed using cryptographically secure random number generation.
    /// </summary>
    /// <returns>A new random Seed instance.</returns>
    public static Seed GenerateRandom()
    {
        var bytes = new byte[Constants.EntropyBitCount / 8];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(bytes);
        return new Seed(bytes);
    }

    /// <summary>
    /// Creates a seed from a byte array.
    /// </summary>
    /// <param name="bytes">The seed bytes.</param>
    /// <returns>A new Seed instance.</returns>
    public static Seed FromBytes(byte[] bytes) => new(bytes);

    /// <summary>
    /// Creates a seed from a BigInteger.
    /// </summary>
    /// <param name="value">The seed value.</param>
    /// <returns>A new Seed instance.</returns>
    public static Seed FromBigInteger(BigInteger value) => new(value);

    /// <summary>
    /// Creates a seed from a hexadecimal string.
    /// </summary>
    /// <param name="hex">The hexadecimal string (with or without 0x prefix).</param>
    /// <returns>A new Seed instance.</returns>
    /// <exception cref="ArgumentException">Thrown when the hex string is invalid.</exception>
    public static Seed FromHex(string hex)
    {
        ArgumentNullException.ThrowIfNull(hex);
        
        // Remove 0x prefix if present
        if (hex.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            hex = hex[2..];
        }

        if (hex.Length != 32) // 128 bits = 32 hex characters
        {
            throw new ArgumentException("Hex string must be exactly 32 characters (128 bits)", nameof(hex));
        }

        try
        {
            var bytes = Convert.FromHexString(hex);
            return new Seed(bytes);
        }
        catch (FormatException ex)
        {
            throw new ArgumentException("Invalid hex string format", nameof(hex), ex);
        }
    }

    /// <summary>
    /// Gets the seed as a byte array (creates a copy).
    /// </summary>
    /// <returns>A copy of the seed bytes.</returns>
    public byte[] ToBytes()
    {
        ThrowIfDisposed();
        var copy = new byte[_bytes.Length];
        _bytes.CopyTo(copy, 0);
        return copy;
    }

    /// <summary>
    /// Gets the seed as a BigInteger.
    /// </summary>
    /// <returns>The seed as a BigInteger.</returns>
    public BigInteger ToBigInteger()
    {
        ThrowIfDisposed();
        return new BigInteger(_bytes, isUnsigned: true, isBigEndian: true);
    }

    /// <summary>
    /// Gets the seed as a hexadecimal string.
    /// </summary>
    /// <returns>The seed as a lowercase hexadecimal string.</returns>
    public string ToHex()
    {
        ThrowIfDisposed();
        return Convert.ToHexString(_bytes).ToLowerInvariant();
    }

    /// <summary>
    /// Securely copies the seed bytes to a span.
    /// </summary>
    /// <param name="destination">The destination span.</param>
    /// <exception cref="ArgumentException">Thrown when destination is too small.</exception>
    public void CopyTo(Span<byte> destination)
    {
        ThrowIfDisposed();
        if (destination.Length < _bytes.Length)
        {
            throw new ArgumentException("Destination span is too small", nameof(destination));
        }
        
        _bytes.AsSpan().CopyTo(destination);
    }

    /// <summary>
    /// Determines whether the specified Seed is equal to this instance.
    /// </summary>
    /// <param name="other">The Seed to compare with this instance.</param>
    /// <returns>true if the specified Seed is equal to this instance; otherwise, false.</returns>
    public bool Equals(Seed? other)
    {
        if (other is null) return false;
        if (ReferenceEquals(this, other)) return true;
        
        ThrowIfDisposed();
        other.ThrowIfDisposed();
        
        return _bytes.AsSpan().SequenceEqual(other._bytes.AsSpan());
    }

    /// <summary>
    /// Determines whether the specified object is equal to this instance.
    /// </summary>
    /// <param name="obj">The object to compare with this instance.</param>
    /// <returns>true if the specified object is equal to this instance; otherwise, false.</returns>
    public override bool Equals(object? obj) => obj is Seed other && Equals(other);

    /// <summary>
    /// Returns a hash code for this instance.
    /// </summary>
    /// <returns>A hash code for this instance.</returns>
    public override int GetHashCode()
    {
        ThrowIfDisposed();
        var hash = new HashCode();
        hash.AddBytes(_bytes);
        return hash.ToHashCode();
    }

    /// <summary>
    /// Returns a string representation of this seed (truncated for security).
    /// </summary>
    /// <returns>A string representation of this seed.</returns>
    public override string ToString()
    {
        if (_disposed)
        {
            return "Seed(disposed)";
        }
        
        var hex = ToHex();
        return $"Seed({hex[..8]}...)"; // Show only first 4 bytes for security
    }

    /// <summary>
    /// Disposes of the seed, securely clearing sensitive data.
    /// </summary>
    public void Dispose()
    {
        if (!_disposed)
        {
            // Securely clear the seed bytes
            _bytes.AsSpan().Clear();
            _disposed = true;
        }
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }

    /// <summary>
    /// Determines whether two Seed instances are equal.
    /// </summary>
    /// <param name="left">The first Seed to compare.</param>
    /// <param name="right">The second Seed to compare.</param>
    /// <returns>true if the Seed instances are equal; otherwise, false.</returns>
    public static bool operator ==(Seed? left, Seed? right) => 
        ReferenceEquals(left, right) || (left?.Equals(right) ?? false);

    /// <summary>
    /// Determines whether two Seed instances are not equal.
    /// </summary>
    /// <param name="left">The first Seed to compare.</param>
    /// <param name="right">The second Seed to compare.</param>
    /// <returns>true if the Seed instances are not equal; otherwise, false.</returns>
    public static bool operator !=(Seed? left, Seed? right) => !(left == right);
}