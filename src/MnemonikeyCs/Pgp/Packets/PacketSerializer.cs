using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace MnemonikeyCs.Pgp.Packets;

/// <summary>
/// Provides OpenPGP packet serialization functionality according to RFC 4880.
/// </summary>
public static class PacketSerializer
{
    /// <summary>
    /// Writes a packet header to the output stream.
    /// </summary>
    /// <param name="output">The output stream.</param>
    /// <param name="packetType">The packet type.</param>
    /// <param name="length">The packet body length.</param>
    public static void WritePacketHeader(Stream output, PacketType packetType, long length)
    {
        ArgumentNullException.ThrowIfNull(output);

        // Use new packet format (RFC 4880 Section 4.2.2)
        if (length < 192)
        {
            // One-octet length
            output.WriteByte((byte)(0xC0 | (byte)packetType));
            output.WriteByte((byte)length);
        }
        else if (length < 8384)
        {
            // Two-octet length
            output.WriteByte((byte)(0xC0 | (byte)packetType));
            length -= 192;
            output.WriteByte((byte)(((length >> 8) & 0xFF) + 192));
            output.WriteByte((byte)(length & 0xFF));
        }
        else
        {
            // Five-octet length
            output.WriteByte((byte)(0xC0 | (byte)packetType));
            output.WriteByte(0xFF);
            output.WriteByte((byte)((length >> 24) & 0xFF));
            output.WriteByte((byte)((length >> 16) & 0xFF));
            output.WriteByte((byte)((length >> 8) & 0xFF));
            output.WriteByte((byte)(length & 0xFF));
        }
    }

    /// <summary>
    /// Writes a multi-precision integer (MPI) to the output stream.
    /// </summary>
    /// <param name="output">The output stream.</param>
    /// <param name="data">The integer data.</param>
    public static void WriteMPI(Stream output, byte[] data)
    {
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(data);

        // Remove leading zeros
        int startIndex = 0;
        while (startIndex < data.Length && data[startIndex] == 0)
        {
            startIndex++;
        }

        if (startIndex == data.Length)
        {
            // All zeros - write zero MPI
            output.WriteByte(0);
            output.WriteByte(0);
            return;
        }

        var significantBytes = data.Length - startIndex;
        var bitCount = (significantBytes - 1) * 8;
        
        // Count bits in the most significant byte
        var msb = data[startIndex];
        if (msb >= 0x80) bitCount += 8;
        else if (msb >= 0x40) bitCount += 7;
        else if (msb >= 0x20) bitCount += 6;
        else if (msb >= 0x10) bitCount += 5;
        else if (msb >= 0x08) bitCount += 4;
        else if (msb >= 0x04) bitCount += 3;
        else if (msb >= 0x02) bitCount += 2;
        else bitCount += 1;

        // Write bit count (2 bytes, big-endian)
        output.WriteByte((byte)((bitCount >> 8) & 0xFF));
        output.WriteByte((byte)(bitCount & 0xFF));

        // Write significant bytes
        output.Write(data, startIndex, significantBytes);
    }

    /// <summary>
    /// Writes a timestamp to the output stream.
    /// </summary>
    /// <param name="output">The output stream.</param>
    /// <param name="timestamp">The timestamp.</param>
    public static void WriteTimestamp(Stream output, DateTime timestamp)
    {
        ArgumentNullException.ThrowIfNull(output);

        var unixTimestamp = (uint)((DateTimeOffset)timestamp).ToUnixTimeSeconds();
        WriteUInt32(output, unixTimestamp);
    }

    /// <summary>
    /// Writes a 32-bit unsigned integer in big-endian format.
    /// </summary>
    /// <param name="output">The output stream.</param>
    /// <param name="value">The value to write.</param>
    public static void WriteUInt32(Stream output, uint value)
    {
        ArgumentNullException.ThrowIfNull(output);

        output.WriteByte((byte)((value >> 24) & 0xFF));
        output.WriteByte((byte)((value >> 16) & 0xFF));
        output.WriteByte((byte)((value >> 8) & 0xFF));
        output.WriteByte((byte)(value & 0xFF));
    }

    /// <summary>
    /// Writes a 16-bit unsigned integer in big-endian format.
    /// </summary>
    /// <param name="output">The output stream.</param>
    /// <param name="value">The value to write.</param>
    public static void WriteUInt16(Stream output, ushort value)
    {
        ArgumentNullException.ThrowIfNull(output);

        output.WriteByte((byte)((value >> 8) & 0xFF));
        output.WriteByte((byte)(value & 0xFF));
    }

    /// <summary>
    /// Writes a string as UTF-8 bytes.
    /// </summary>
    /// <param name="output">The output stream.</param>
    /// <param name="value">The string to write.</param>
    public static void WriteString(Stream output, string value)
    {
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(value);

        var bytes = Encoding.UTF8.GetBytes(value);
        output.Write(bytes);
    }

    /// <summary>
    /// Writes a subpacket to the output stream.
    /// </summary>
    /// <param name="output">The output stream.</param>
    /// <param name="type">The subpacket type.</param>
    /// <param name="data">The subpacket data.</param>
    /// <param name="critical">Whether the subpacket is critical.</param>
    public static void WriteSubpacket(Stream output, SignatureSubpacketType type, byte[] data, bool critical = false)
    {
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(data);

        var packetLength = data.Length + 1; // +1 for type byte

        // Write subpacket length
        if (packetLength < 192)
        {
            output.WriteByte((byte)packetLength);
        }
        else if (packetLength < 8384)
        {
            packetLength -= 192;
            output.WriteByte((byte)(((packetLength >> 8) & 0xFF) + 192));
            output.WriteByte((byte)(packetLength & 0xFF));
        }
        else
        {
            output.WriteByte(0xFF);
            WriteUInt32(output, (uint)packetLength);
        }

        // Write subpacket type (with critical bit if needed)
        var typeValue = (byte)type;
        if (critical)
        {
            typeValue |= 0x80;
        }
        output.WriteByte(typeValue);

        // Write subpacket data
        output.Write(data);
    }

    /// <summary>
    /// Creates a signature creation time subpacket.
    /// </summary>
    /// <param name="creationTime">The signature creation time.</param>
    /// <returns>The subpacket data.</returns>
    public static byte[] CreateSignatureCreationTimeSubpacket(DateTime creationTime)
    {
        using var stream = new MemoryStream();
        WriteTimestamp(stream, creationTime);
        return stream.ToArray();
    }

    /// <summary>
    /// Creates an issuer subpacket.
    /// </summary>
    /// <param name="keyId">The 8-byte issuer key ID.</param>
    /// <returns>The subpacket data.</returns>
    public static byte[] CreateIssuerSubpacket(byte[] keyId)
    {
        ArgumentNullException.ThrowIfNull(keyId);
        
        if (keyId.Length != 8)
            throw new ArgumentException("Key ID must be exactly 8 bytes", nameof(keyId));

        var data = new byte[keyId.Length];
        keyId.CopyTo(data, 0);
        return data;
    }

    /// <summary>
    /// Creates a key flags subpacket.
    /// </summary>
    /// <param name="flags">The key usage flags.</param>
    /// <returns>The subpacket data.</returns>
    public static byte[] CreateKeyFlagsSubpacket(byte flags)
    {
        return new[] { flags };
    }

    /// <summary>
    /// Creates a preferred hash algorithms subpacket.
    /// </summary>
    /// <param name="algorithms">The preferred hash algorithms.</param>
    /// <returns>The subpacket data.</returns>
    public static byte[] CreatePreferredHashAlgorithmsSubpacket(params HashAlgorithm[] algorithms)
    {
        ArgumentNullException.ThrowIfNull(algorithms);

        var data = new byte[algorithms.Length];
        for (int i = 0; i < algorithms.Length; i++)
        {
            data[i] = (byte)algorithms[i];
        }
        return data;
    }

    /// <summary>
    /// Creates a preferred symmetric algorithms subpacket.
    /// </summary>
    /// <param name="algorithms">The preferred symmetric algorithms.</param>
    /// <returns>The subpacket data.</returns>
    public static byte[] CreatePreferredSymmetricAlgorithmsSubpacket(params SymmetricAlgorithm[] algorithms)
    {
        ArgumentNullException.ThrowIfNull(algorithms);

        var data = new byte[algorithms.Length];
        for (int i = 0; i < algorithms.Length; i++)
        {
            data[i] = (byte)algorithms[i];
        }
        return data;
    }

    /// <summary>
    /// Creates a preferred compression algorithms subpacket.
    /// </summary>
    /// <param name="algorithms">The preferred compression algorithms.</param>
    /// <returns>The subpacket data.</returns>
    public static byte[] CreatePreferredCompressionAlgorithmsSubpacket(params CompressionAlgorithm[] algorithms)
    {
        ArgumentNullException.ThrowIfNull(algorithms);

        var data = new byte[algorithms.Length];
        for (int i = 0; i < algorithms.Length; i++)
        {
            data[i] = (byte)algorithms[i];
        }
        return data;
    }

    /// <summary>
    /// Calculates the total length of subpackets.
    /// </summary>
    /// <param name="subpackets">The subpacket data collection.</param>
    /// <returns>The total length in bytes.</returns>
    public static int CalculateSubpacketsLength(IEnumerable<(SignatureSubpacketType type, byte[] data, bool critical)> subpackets)
    {
        ArgumentNullException.ThrowIfNull(subpackets);

        int totalLength = 0;
        foreach (var (type, data, critical) in subpackets)
        {
            var packetLength = data.Length + 1; // +1 for type byte

            // Add length of length encoding
            if (packetLength < 192)
            {
                totalLength += 1;
            }
            else if (packetLength < 8384)
            {
                totalLength += 2;
            }
            else
            {
                totalLength += 5;
            }

            totalLength += packetLength;
        }
        return totalLength;
    }

    /// <summary>
    /// Writes multiple subpackets to the output stream.
    /// </summary>
    /// <param name="output">The output stream.</param>
    /// <param name="subpackets">The subpackets to write.</param>
    public static void WriteSubpackets(Stream output, IEnumerable<(SignatureSubpacketType type, byte[] data, bool critical)> subpackets)
    {
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(subpackets);

        foreach (var (type, data, critical) in subpackets)
        {
            WriteSubpacket(output, type, data, critical);
        }
    }
}