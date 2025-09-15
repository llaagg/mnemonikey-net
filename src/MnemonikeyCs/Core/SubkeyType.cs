namespace MnemonikeyCs.Core;

/// <summary>
/// Represents the type of a PGP subkey.
/// </summary>
public enum SubkeyType
{
    /// <summary>
    /// Encryption subkey for encrypting communications and storage.
    /// Uses Curve25519 (ECDH) algorithm.
    /// </summary>
    Encryption,

    /// <summary>
    /// Authentication subkey for proving identity.
    /// Uses Ed25519 (EdDSA) algorithm.
    /// </summary>
    Authentication,

    /// <summary>
    /// Signing subkey for creating digital signatures.
    /// Uses Ed25519 (EdDSA) algorithm.
    /// </summary>
    Signing
}

/// <summary>
/// Extension methods for SubkeyType.
/// </summary>
public static class SubkeyTypeExtensions
{
    /// <summary>
    /// Converts a SubkeyType to its string representation used in HKDF info.
    /// </summary>
    /// <param name="subkeyType">The subkey type.</param>
    /// <returns>The string representation.</returns>
    public static string ToInfoString(this SubkeyType subkeyType)
    {
        return subkeyType switch
        {
            SubkeyType.Encryption => "encryption",
            SubkeyType.Authentication => "authentication",
            SubkeyType.Signing => "signing",
            _ => throw new ArgumentOutOfRangeException(nameof(subkeyType), subkeyType, "Unknown subkey type")
        };
    }

    /// <summary>
    /// Parses a string representation to a SubkeyType.
    /// </summary>
    /// <param name="value">The string value.</param>
    /// <returns>The SubkeyType.</returns>
    /// <exception cref="ArgumentException">Thrown when the value is not a valid SubkeyType.</exception>
    public static SubkeyType ParseSubkeyType(string value)
    {
        return value?.ToLowerInvariant() switch
        {
            "encryption" => SubkeyType.Encryption,
            "authentication" => SubkeyType.Authentication,
            "signing" => SubkeyType.Signing,
            _ => throw new ArgumentException($"Invalid subkey type: {value}", nameof(value))
        };
    }
}