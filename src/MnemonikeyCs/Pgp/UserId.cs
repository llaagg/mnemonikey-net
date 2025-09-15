using System;
using System.Text.RegularExpressions;

namespace MnemonikeyCs.Pgp;

/// <summary>
/// Represents a PGP User ID with parsing and validation capabilities.
/// </summary>
public sealed class UserId : IEquatable<UserId>
{
    private static readonly Regex EmailRegex = new(
        @"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex NameEmailRegex = new(
        @"^(.+?)\s*<(.+)>$",
        RegexOptions.Compiled);

    /// <summary>
    /// Gets the full User ID string.
    /// </summary>
    public string Value { get; }

    /// <summary>
    /// Gets the name portion of the User ID, if present.
    /// </summary>
    public string? Name { get; }

    /// <summary>
    /// Gets the email address portion of the User ID, if present.
    /// </summary>
    public string? Email { get; }

    /// <summary>
    /// Gets whether this User ID has a name component.
    /// </summary>
    public bool HasName => !string.IsNullOrEmpty(Name);

    /// <summary>
    /// Gets whether this User ID has an email component.
    /// </summary>
    public bool HasEmail => !string.IsNullOrEmpty(Email);

    /// <summary>
    /// Gets whether this User ID is in the standard "Name &lt;email&gt;" format.
    /// </summary>
    public bool IsNameEmailFormat => HasName && HasEmail;

    /// <summary>
    /// Gets whether this User ID contains only an email address.
    /// </summary>
    public bool IsEmailOnly => HasEmail && !HasName;

    /// <summary>
    /// Gets whether this User ID contains only a name.
    /// </summary>
    public bool IsNameOnly => HasName && !HasEmail;

    /// <summary>
    /// Initializes a new instance of the UserId class.
    /// </summary>
    /// <param name="value">The User ID string.</param>
    /// <exception cref="ArgumentException">Thrown when value is null, empty, or whitespace.</exception>
    private UserId(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);

        Value = value.Trim();
        (Name, Email) = ParseUserId(Value);
    }

    /// <summary>
    /// Creates a User ID from a string.
    /// </summary>
    /// <param name="value">The User ID string.</param>
    /// <returns>A new UserId instance.</returns>
    /// <exception cref="ArgumentException">Thrown when value is invalid.</exception>
    public static UserId FromString(string value)
    {
        return new UserId(value);
    }

    /// <summary>
    /// Creates a User ID from a name and email address.
    /// </summary>
    /// <param name="name">The user's name.</param>
    /// <param name="email">The user's email address.</param>
    /// <returns>A new UserId instance.</returns>
    /// <exception cref="ArgumentException">Thrown when parameters are invalid.</exception>
    public static UserId Create(string name, string email)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentException.ThrowIfNullOrWhiteSpace(email);

        if (!IsValidEmail(email))
        {
            throw new ArgumentException("Invalid email format", nameof(email));
        }

        var userId = $"{name.Trim()} <{email.Trim()}>";
        return new UserId(userId);
    }

    /// <summary>
    /// Creates a User ID from just a name.
    /// </summary>
    /// <param name="name">The user's name.</param>
    /// <returns>A new UserId instance.</returns>
    /// <exception cref="ArgumentException">Thrown when name is invalid.</exception>
    public static UserId CreateFromName(string name)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        return new UserId(name.Trim());
    }

    /// <summary>
    /// Creates a User ID from just an email address.
    /// </summary>
    /// <param name="email">The user's email address.</param>
    /// <returns>A new UserId instance.</returns>
    /// <exception cref="ArgumentException">Thrown when email is invalid.</exception>
    public static UserId CreateFromEmail(string email)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(email);

        if (!IsValidEmail(email))
        {
            throw new ArgumentException("Invalid email format", nameof(email));
        }

        return new UserId(email.Trim());
    }

    /// <summary>
    /// Attempts to parse a User ID string.
    /// </summary>
    /// <param name="value">The User ID string.</param>
    /// <param name="userId">The parsed UserId, if successful.</param>
    /// <returns>True if parsing was successful, false otherwise.</returns>
    public static bool TryParse(string? value, out UserId? userId)
    {
        userId = null;

        if (string.IsNullOrWhiteSpace(value))
            return false;

        try
        {
            userId = new UserId(value);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Validates the User ID format and content.
    /// </summary>
    /// <returns>True if the User ID is valid, false otherwise.</returns>
    public bool IsValid()
    {
        // User ID must not be empty
        if (string.IsNullOrWhiteSpace(Value))
            return false;

        // If it has an email, it must be valid
        if (HasEmail && !IsValidEmail(Email!))
            return false;

        // User ID must not exceed reasonable length (no official limit, but 255 chars is reasonable)
        if (Value.Length > 255)
            return false;

        // User ID should not contain control characters
        foreach (char c in Value)
        {
            if (char.IsControl(c) && c != '\t')
                return false;
        }

        return true;
    }

    /// <summary>
    /// Gets a normalized version of the User ID suitable for comparison.
    /// </summary>
    /// <returns>The normalized User ID string.</returns>
    public string GetNormalized()
    {
        if (IsNameEmailFormat && Name != null && Email != null)
        {
            // Normalize "Name <email>" format
            return $"{Name.Trim()} <{Email.Trim().ToLowerInvariant()}>";
        }
        else if (IsEmailOnly && Email != null)
        {
            // Normalize email-only format
            return Email.Trim().ToLowerInvariant();
        }
        else
        {
            // For name-only or other formats, just trim
            return Value.Trim();
        }
    }

    /// <summary>
    /// Gets the display name for this User ID.
    /// Returns the name if present, otherwise the email, otherwise the full value.
    /// </summary>
    /// <returns>The display name.</returns>
    public string GetDisplayName()
    {
        if (HasName)
            return Name!;
        
        if (HasEmail)
            return Email!;
        
        return Value;
    }

    /// <summary>
    /// Gets the primary identifier for this User ID.
    /// Returns the email if present, otherwise the name, otherwise the full value.
    /// </summary>
    /// <returns>The primary identifier.</returns>
    public string GetPrimaryIdentifier()
    {
        if (HasEmail)
            return Email!;
        
        if (HasName)
            return Name!;
        
        return Value;
    }

    /// <summary>
    /// Parses a User ID string into name and email components.
    /// </summary>
    /// <param name="value">The User ID string.</param>
    /// <returns>A tuple containing the name and email (either may be null).</returns>
    private static (string? name, string? email) ParseUserId(string value)
    {
        // Try to match "Name <email>" format
        var nameEmailMatch = NameEmailRegex.Match(value);
        if (nameEmailMatch.Success)
        {
            var name = nameEmailMatch.Groups[1].Value.Trim();
            var email = nameEmailMatch.Groups[2].Value.Trim();
            
            if (IsValidEmail(email))
            {
                return (string.IsNullOrEmpty(name) ? null : name, email);
            }
        }

        // Check if the entire value is an email
        if (IsValidEmail(value))
        {
            return (null, value);
        }

        // Otherwise, treat as name only
        return (value, null);
    }

    /// <summary>
    /// Validates an email address format.
    /// </summary>
    /// <param name="email">The email address to validate.</param>
    /// <returns>True if the email format is valid, false otherwise.</returns>
    private static bool IsValidEmail(string? email)
    {
        if (string.IsNullOrWhiteSpace(email))
            return false;

        try
        {
            return EmailRegex.IsMatch(email) && email.Length <= 320; // RFC 5321 limit
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Returns the User ID string.
    /// </summary>
    /// <returns>The User ID string.</returns>
    public override string ToString() => Value;

    /// <summary>
    /// Determines whether the specified UserId is equal to this instance.
    /// </summary>
    /// <param name="other">The UserId to compare.</param>
    /// <returns>True if equal, false otherwise.</returns>
    public bool Equals(UserId? other)
    {
        if (other is null) return false;
        if (ReferenceEquals(this, other)) return true;
        
        // Compare normalized values for case-insensitive email comparison
        return GetNormalized() == other.GetNormalized();
    }

    /// <summary>
    /// Determines whether the specified object is equal to this instance.
    /// </summary>
    /// <param name="obj">The object to compare.</param>
    /// <returns>True if equal, false otherwise.</returns>
    public override bool Equals(object? obj) => obj is UserId other && Equals(other);

    /// <summary>
    /// Returns a hash code for this instance.
    /// </summary>
    /// <returns>A hash code.</returns>
    public override int GetHashCode()
    {
        return GetNormalized().GetHashCode();
    }

    /// <summary>
    /// Determines whether two UserId instances are equal.
    /// </summary>
    /// <param name="left">The first UserId.</param>
    /// <param name="right">The second UserId.</param>
    /// <returns>True if equal, false otherwise.</returns>
    public static bool operator ==(UserId? left, UserId? right)
    {
        return ReferenceEquals(left, right) || (left?.Equals(right) ?? false);
    }

    /// <summary>
    /// Determines whether two UserId instances are not equal.
    /// </summary>
    /// <param name="left">The first UserId.</param>
    /// <param name="right">The second UserId.</param>
    /// <returns>True if not equal, false otherwise.</returns>
    public static bool operator !=(UserId? left, UserId? right)
    {
        return !(left == right);
    }

    /// <summary>
    /// Implicitly converts a string to a UserId.
    /// </summary>
    /// <param name="value">The User ID string.</param>
    /// <returns>A new UserId instance.</returns>
    public static implicit operator UserId(string value) => FromString(value);

    /// <summary>
    /// Implicitly converts a UserId to a string.
    /// </summary>
    /// <param name="userId">The UserId instance.</param>
    /// <returns>The User ID string.</returns>
    public static implicit operator string(UserId userId) => userId?.Value ?? string.Empty;
}