using System;

namespace MnemonikeyCs.Core;

/// <summary>
/// Represents the version of a mnemonic recovery phrase.
/// Version numbers describe how to decode a recovery phrase into a seed and creation time.
/// </summary>
public readonly struct MnemonicVersion : IEquatable<MnemonicVersion>
{
    private readonly byte _value;

    /// <summary>
    /// Initializes a new instance of the MnemonicVersion struct.
    /// </summary>
    /// <param name="value">The version value.</param>
    public MnemonicVersion(byte value)
    {
        if (value > 15) // 4-bit value
        {
            throw new ArgumentOutOfRangeException(nameof(value), value, "Mnemonic version must be between 0 and 15");
        }
        _value = value;
    }

    /// <summary>
    /// Gets the plaintext mnemonic version (0).
    /// </summary>
    public static MnemonicVersion Plaintext => new(0);

    /// <summary>
    /// Gets the encrypted mnemonic version (1).
    /// </summary>
    public static MnemonicVersion Encrypted => new(1);

    /// <summary>
    /// Gets the version value.
    /// </summary>
    public byte Value => _value;

    /// <summary>
    /// Gets a value indicating whether this version represents an encrypted phrase.
    /// </summary>
    public bool IsEncrypted => _value == 1;

    /// <summary>
    /// Gets a value indicating whether this version represents a plaintext phrase.
    /// </summary>
    public bool IsPlaintext => _value == 0;

    /// <summary>
    /// Gets the era associated with this mnemonic version.
    /// Currently, all versions map to era 0.
    /// </summary>
    public Era Era => new(0);

    /// <summary>
    /// Gets the expected number of words for this mnemonic version.
    /// </summary>
    public int WordCount => _value switch
    {
        0 => 14, // Plaintext: 14 words
        1 => 16, // Encrypted: 16 words
        _ => throw new NotSupportedException($"Mnemonic version {_value} is not supported")
    };

    /// <summary>
    /// Gets the total number of bits in the payload for this version.
    /// </summary>
    public int PayloadBitCount => WordCount * Constants.BitsPerWord;

    /// <summary>
    /// Checks if this mnemonic version is supported.
    /// </summary>
    /// <exception cref="NotSupportedException">Thrown when the version is not supported.</exception>
    public void Check()
    {
        if (_value > 1)
        {
            throw new NotSupportedException($"Mnemonic version {_value} is not supported. Only versions 0 and 1 are currently supported.");
        }
    }

    /// <summary>
    /// Determines whether the specified MnemonicVersion is equal to this instance.
    /// </summary>
    /// <param name="other">The MnemonicVersion to compare with this instance.</param>
    /// <returns>true if the specified MnemonicVersion is equal to this instance; otherwise, false.</returns>
    public bool Equals(MnemonicVersion other) => _value == other._value;

    /// <summary>
    /// Determines whether the specified object is equal to this instance.
    /// </summary>
    /// <param name="obj">The object to compare with this instance.</param>
    /// <returns>true if the specified object is equal to this instance; otherwise, false.</returns>
    public override bool Equals(object? obj) => obj is MnemonicVersion other && Equals(other);

    /// <summary>
    /// Returns a hash code for this instance.
    /// </summary>
    /// <returns>A hash code for this instance.</returns>
    public override int GetHashCode() => _value.GetHashCode();

    /// <summary>
    /// Returns a string representation of this mnemonic version.
    /// </summary>
    /// <returns>A string representation of this mnemonic version.</returns>
    public override string ToString() => $"Version {_value} ({(IsEncrypted ? "Encrypted" : "Plaintext")})";

    /// <summary>
    /// Determines whether two MnemonicVersion instances are equal.
    /// </summary>
    /// <param name="left">The first MnemonicVersion to compare.</param>
    /// <param name="right">The second MnemonicVersion to compare.</param>
    /// <returns>true if the MnemonicVersion instances are equal; otherwise, false.</returns>
    public static bool operator ==(MnemonicVersion left, MnemonicVersion right) => left.Equals(right);

    /// <summary>
    /// Determines whether two MnemonicVersion instances are not equal.
    /// </summary>
    /// <param name="left">The first MnemonicVersion to compare.</param>
    /// <param name="right">The second MnemonicVersion to compare.</param>
    /// <returns>true if the MnemonicVersion instances are not equal; otherwise, false.</returns>
    public static bool operator !=(MnemonicVersion left, MnemonicVersion right) => !left.Equals(right);

    /// <summary>
    /// Implicitly converts a byte to a MnemonicVersion.
    /// </summary>
    /// <param name="value">The byte value.</param>
    /// <returns>A MnemonicVersion with the specified value.</returns>
    public static implicit operator MnemonicVersion(byte value) => new(value);

    /// <summary>
    /// Implicitly converts a MnemonicVersion to a byte.
    /// </summary>
    /// <param name="version">The MnemonicVersion to convert.</param>
    /// <returns>The byte value of the MnemonicVersion.</returns>
    public static implicit operator byte(MnemonicVersion version) => version._value;
}