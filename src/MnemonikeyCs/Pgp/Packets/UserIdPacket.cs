using System;
using System.IO;
using System.Text;

namespace MnemonikeyCs.Pgp.Packets;

/// <summary>
/// Represents an OpenPGP User ID packet.
/// </summary>
public sealed class UserIdPacket
{
    /// <summary>
    /// Gets the user ID string.
    /// </summary>
    public string UserId { get; }

    /// <summary>
    /// Gets the UTF-8 encoded user ID bytes.
    /// </summary>
    public byte[] UserIdBytes { get; }

    /// <summary>
    /// Initializes a new instance of the UserIdPacket class.
    /// </summary>
    /// <param name="userId">The user ID string.</param>
    /// <exception cref="ArgumentNullException">Thrown when userId is null.</exception>
    /// <exception cref="ArgumentException">Thrown when userId is empty or whitespace.</exception>
    public UserIdPacket(string userId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userId);
        
        UserId = userId;
        UserIdBytes = Encoding.UTF8.GetBytes(userId);
    }

    /// <summary>
    /// Creates a User ID packet from a name and email address.
    /// </summary>
    /// <param name="name">The user's name.</param>
    /// <param name="email">The user's email address.</param>
    /// <returns>A new UserIdPacket instance.</returns>
    /// <exception cref="ArgumentException">Thrown when name or email is invalid.</exception>
    public static UserIdPacket Create(string name, string email)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentException.ThrowIfNullOrWhiteSpace(email);

        // Validate email format (basic validation)
        if (!IsValidEmail(email))
        {
            throw new ArgumentException("Invalid email format", nameof(email));
        }

        var userId = $"{name} <{email}>";
        return new UserIdPacket(userId);
    }

    /// <summary>
    /// Creates a User ID packet from just a name.
    /// </summary>
    /// <param name="name">The user's name.</param>
    /// <returns>A new UserIdPacket instance.</returns>
    /// <exception cref="ArgumentException">Thrown when name is invalid.</exception>
    public static UserIdPacket CreateFromName(string name)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        return new UserIdPacket(name);
    }

    /// <summary>
    /// Creates a User ID packet from just an email address.
    /// </summary>
    /// <param name="email">The user's email address.</param>
    /// <returns>A new UserIdPacket instance.</returns>
    /// <exception cref="ArgumentException">Thrown when email is invalid.</exception>
    public static UserIdPacket CreateFromEmail(string email)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(email);

        if (!IsValidEmail(email))
        {
            throw new ArgumentException("Invalid email format", nameof(email));
        }

        return new UserIdPacket(email);
    }

    /// <summary>
    /// Serializes the User ID packet to a byte array.
    /// </summary>
    /// <returns>The serialized packet data.</returns>
    public byte[] Serialize()
    {
        using var output = new MemoryStream();
        
        // Write packet header
        PacketSerializer.WritePacketHeader(output, PacketType.UserId, UserIdBytes.Length);
        
        // Write User ID bytes
        output.Write(UserIdBytes);
        
        return output.ToArray();
    }

    /// <summary>
    /// Gets the User ID data for signature calculation.
    /// This includes the packet type prefix required for signature hashing.
    /// </summary>
    /// <returns>The User ID data formatted for signature calculation.</returns>
    public byte[] GetSignatureData()
    {
        using var output = new MemoryStream();
        
        // For signature calculation, User ID packets are prefixed with 0xB4
        output.WriteByte(0xB4);
        
        // Write the length as a 32-bit big-endian integer
        PacketSerializer.WriteUInt32(output, (uint)UserIdBytes.Length);
        
        // Write the User ID bytes
        output.Write(UserIdBytes);
        
        return output.ToArray();
    }

    /// <summary>
    /// Extracts the name portion from the User ID.
    /// </summary>
    /// <returns>The name, or null if not in "Name &lt;email&gt;" format.</returns>
    public string? ExtractName()
    {
        var angleIndex = UserId.IndexOf('<');
        if (angleIndex <= 0)
        {
            // Not in "Name <email>" format
            return null;
        }

        return UserId[..angleIndex].Trim();
    }

    /// <summary>
    /// Extracts the email portion from the User ID.
    /// </summary>
    /// <returns>The email address, or null if not found.</returns>
    public string? ExtractEmail()
    {
        var startIndex = UserId.IndexOf('<');
        var endIndex = UserId.LastIndexOf('>');
        
        if (startIndex < 0 || endIndex < 0 || startIndex >= endIndex)
        {
            // Check if the entire User ID is an email address
            if (IsValidEmail(UserId))
            {
                return UserId;
            }
            return null;
        }

        return UserId.Substring(startIndex + 1, endIndex - startIndex - 1);
    }

    /// <summary>
    /// Checks if the User ID contains an email address.
    /// </summary>
    /// <returns>True if an email address is present, false otherwise.</returns>
    public bool HasEmail()
    {
        return ExtractEmail() != null;
    }

    /// <summary>
    /// Checks if the User ID contains a name.
    /// </summary>
    /// <returns>True if a name is present, false otherwise.</returns>
    public bool HasName()
    {
        return ExtractName() != null;
    }

    /// <summary>
    /// Performs basic email validation.
    /// </summary>
    /// <param name="email">The email address to validate.</param>
    /// <returns>True if the email appears valid, false otherwise.</returns>
    private static bool IsValidEmail(string email)
    {
        if (string.IsNullOrWhiteSpace(email))
            return false;

        // Basic email validation - must contain @ and have parts before and after
        var atIndex = email.IndexOf('@');
        if (atIndex <= 0 || atIndex >= email.Length - 1)
            return false;

        // Must not contain multiple @ symbols
        if (email.IndexOf('@', atIndex + 1) >= 0)
            return false;

        // Basic domain validation - must contain at least one dot after @
        var domain = email[(atIndex + 1)..];
        if (!domain.Contains('.'))
            return false;

        return true;
    }

    /// <summary>
    /// Returns a string representation of the User ID.
    /// </summary>
    /// <returns>The User ID string.</returns>
    public override string ToString()
    {
        return UserId;
    }

    /// <summary>
    /// Determines whether the specified object is equal to this User ID packet.
    /// </summary>
    /// <param name="obj">The object to compare.</param>
    /// <returns>True if equal, false otherwise.</returns>
    public override bool Equals(object? obj)
    {
        return obj is UserIdPacket other && UserId == other.UserId;
    }

    /// <summary>
    /// Returns a hash code for this User ID packet.
    /// </summary>
    /// <returns>A hash code.</returns>
    public override int GetHashCode()
    {
        return UserId.GetHashCode();
    }

    /// <summary>
    /// Determines whether two User ID packets are equal.
    /// </summary>
    /// <param name="left">The first packet.</param>
    /// <param name="right">The second packet.</param>
    /// <returns>True if equal, false otherwise.</returns>
    public static bool operator ==(UserIdPacket? left, UserIdPacket? right)
    {
        return ReferenceEquals(left, right) || (left?.Equals(right) ?? false);
    }

    /// <summary>
    /// Determines whether two User ID packets are not equal.
    /// </summary>
    /// <param name="left">The first packet.</param>
    /// <param name="right">The second packet.</param>
    /// <returns>True if not equal, false otherwise.</returns>
    public static bool operator !=(UserIdPacket? left, UserIdPacket? right)
    {
        return !(left == right);
    }
}