using System;

namespace MnemonikeyCs.Core;

/// <summary>
/// Represents the era (version) of the key derivation algorithm.
/// Eras describe how to derive PGP keys from a seed and creation time.
/// </summary>
public readonly struct Era : IEquatable<Era>
{
    private readonly byte _value;

    /// <summary>
    /// Initializes a new instance of the Era struct.
    /// </summary>
    /// <param name="value">The era value.</param>
    public Era(byte value)
    {
        _value = value;
    }

    /// <summary>
    /// Gets the current era (0).
    /// </summary>
    public static Era Current => new(0);

    /// <summary>
    /// Gets the era value.
    /// </summary>
    public byte Value => _value;

    /// <summary>
    /// Checks if this era is supported.
    /// </summary>
    /// <exception cref="NotSupportedException">Thrown when the era is not supported.</exception>
    public void Check()
    {
        if (_value > 0)
        {
            throw new NotSupportedException($"Era {_value} is not supported. Only era 0 is currently supported.");
        }
    }

    /// <summary>
    /// Determines whether the specified Era is equal to this instance.
    /// </summary>
    /// <param name="other">The Era to compare with this instance.</param>
    /// <returns>true if the specified Era is equal to this instance; otherwise, false.</returns>
    public bool Equals(Era other) => _value == other._value;

    /// <summary>
    /// Determines whether the specified object is equal to this instance.
    /// </summary>
    /// <param name="obj">The object to compare with this instance.</param>
    /// <returns>true if the specified object is equal to this instance; otherwise, false.</returns>
    public override bool Equals(object? obj) => obj is Era other && Equals(other);

    /// <summary>
    /// Returns a hash code for this instance.
    /// </summary>
    /// <returns>A hash code for this instance.</returns>
    public override int GetHashCode() => _value.GetHashCode();

    /// <summary>
    /// Returns a string representation of this era.
    /// </summary>
    /// <returns>A string representation of this era.</returns>
    public override string ToString() => $"Era {_value}";

    /// <summary>
    /// Determines whether two Era instances are equal.
    /// </summary>
    /// <param name="left">The first Era to compare.</param>
    /// <param name="right">The second Era to compare.</param>
    /// <returns>true if the Era instances are equal; otherwise, false.</returns>
    public static bool operator ==(Era left, Era right) => left.Equals(right);

    /// <summary>
    /// Determines whether two Era instances are not equal.
    /// </summary>
    /// <param name="left">The first Era to compare.</param>
    /// <param name="right">The second Era to compare.</param>
    /// <returns>true if the Era instances are not equal; otherwise, false.</returns>
    public static bool operator !=(Era left, Era right) => !left.Equals(right);

    /// <summary>
    /// Implicitly converts a byte to an Era.
    /// </summary>
    /// <param name="value">The byte value.</param>
    /// <returns>An Era with the specified value.</returns>
    public static implicit operator Era(byte value) => new(value);

    /// <summary>
    /// Implicitly converts an Era to a byte.
    /// </summary>
    /// <param name="era">The Era to convert.</param>
    /// <returns>The byte value of the Era.</returns>
    public static implicit operator byte(Era era) => era._value;
}