using System;
using System.Numerics;
using FluentAssertions;
using MnemonikeyCs.Core;
using Xunit;
using Xunit.Abstractions;

namespace MnemonikeyCs.Tests.Core;

/// <summary>
/// Tests for the BitBuffer class.
/// </summary>
public sealed class BitBufferTests : TestBase
{
    public BitBufferTests(ITestOutputHelper output) : base(output)
    {
    }

    [Fact]
    public void Constructor_Empty_ShouldCreateEmptyBuffer()
    {
        // Act
        var buffer = new BitBuffer();

        // Assert
        buffer.BitLength.Should().Be(0);
        buffer.Data.Should().Be(BigInteger.Zero);
        buffer.ToBytes().Should().BeEmpty();

        Log("Empty BitBuffer created successfully");
    }

    [Theory]
    [InlineData(0, 0)]
    [InlineData(5, 4)]
    [InlineData(255, 8)]
    [InlineData(1023, 10)]
    public void Constructor_WithInitialValue_ShouldStoreValue(int value, int bitCount)
    {
        // Act
        var buffer = new BitBuffer(new BigInteger(value), bitCount);

        // Assert
        buffer.BitLength.Should().Be(bitCount);
        buffer.Data.Should().Be(new BigInteger(value));

        Log($"BitBuffer created with value {value} ({bitCount} bits)");
    }

    [Fact]
    public void Constructor_NegativeValue_ShouldThrowException()
    {
        // Act & Assert
        var act = () => new BitBuffer(new BigInteger(-1), 8);
        act.Should().Throw<ArgumentOutOfRangeException>();

        Log("Correctly rejected negative value");
    }

    [Fact]
    public void Constructor_ValueExceedsBitCount_ShouldThrowException()
    {
        // Act & Assert
        var act = () => new BitBuffer(new BigInteger(256), 8); // 256 needs 9 bits
        act.Should().Throw<ArgumentException>();

        Log("Correctly rejected value that exceeds bit count");
    }

    [Theory]
    [InlineData(15, 4, 4, 15)]      // Append 15 (4 bits) to empty, expect 15 (4 bits total)
    [InlineData(7, 3, 3, 7)]        // Append 7 (3 bits) to empty, expect 7 (3 bits total)
    [InlineData(255, 8, 8, 255)]    // Append 255 (8 bits) to empty, expect 255 (8 bits total)
    public void AppendTrailingBits_ToEmptyBuffer_ShouldAppendCorrectly(int value, int bitCount, int expectedBitLength, int expectedValue)
    {
        // Arrange
        var buffer = new BitBuffer();

        // Act
        buffer.AppendTrailingBits(new BigInteger(value), bitCount);

        // Assert
        buffer.BitLength.Should().Be(expectedBitLength);
        buffer.Data.Should().Be(new BigInteger(expectedValue));

        Log($"Appended {value} ({bitCount} bits) to empty buffer, result: {buffer.Data} ({buffer.BitLength} bits)");
    }

    [Fact]
    public void AppendTrailingBits_ToNonEmptyBuffer_ShouldShiftAndAppend()
    {
        // Arrange - Start with 5 (binary: 101, 3 bits)
        var buffer = new BitBuffer(new BigInteger(5), 3);

        // Act - Append 3 (binary: 11, 2 bits)
        // Expected: 101 << 2 | 11 = 10100 | 11 = 10111 = 23
        buffer.AppendTrailingBits(new BigInteger(3), 2);

        // Assert
        buffer.BitLength.Should().Be(5);
        buffer.Data.Should().Be(new BigInteger(23)); // 10111 in binary

        Log($"Appended 3 (2 bits) to buffer containing 5 (3 bits), result: {buffer.Data} ({buffer.BitLength} bits)");
    }

    [Fact]
    public void AppendLeadingBits_ToEmptyBuffer_ShouldAppendCorrectly()
    {
        // Arrange
        var buffer = new BitBuffer();

        // Act
        buffer.AppendLeadingBits(new BigInteger(7), 3);

        // Assert
        buffer.BitLength.Should().Be(3);
        buffer.Data.Should().Be(new BigInteger(7));

        Log($"Appended 7 as leading bits to empty buffer, result: {buffer.Data} ({buffer.BitLength} bits)");
    }

    [Fact]
    public void AppendLeadingBits_ToNonEmptyBuffer_ShouldInsertAtFront()
    {
        // Arrange - Start with 5 (binary: 101, 3 bits)
        var buffer = new BitBuffer(new BigInteger(5), 3);

        // Act - Append 3 (binary: 11, 2 bits) as leading bits
        // Expected: 11 << 3 | 101 = 11000 | 101 = 11101 = 29
        buffer.AppendLeadingBits(new BigInteger(3), 2);

        // Assert
        buffer.BitLength.Should().Be(5);
        buffer.Data.Should().Be(new BigInteger(29)); // 11101 in binary

        Log($"Appended 3 (2 bits) as leading bits to buffer containing 5 (3 bits), result: {buffer.Data} ({buffer.BitLength} bits)");
    }

    [Fact]
    public void ExtractTrailingBits_ShouldRemoveBitsFromEnd()
    {
        // Arrange - Start with 23 (binary: 10111, 5 bits)
        var buffer = new BitBuffer(new BigInteger(23), 5);

        // Act - Extract 2 trailing bits (should get 11 = 3, leaving 101 = 5)
        var extracted = buffer.ExtractTrailingBits(2);

        // Assert
        extracted.Should().Be(new BigInteger(3)); // 11 in binary
        buffer.BitLength.Should().Be(3);
        buffer.Data.Should().Be(new BigInteger(5)); // 101 in binary

        Log($"Extracted 2 trailing bits: {extracted}, remaining: {buffer.Data} ({buffer.BitLength} bits)");
    }

    [Fact]
    public void ExtractLeadingBits_ShouldRemoveBitsFromStart()
    {
        // Arrange - Start with 23 (binary: 10111, 5 bits)
        var buffer = new BitBuffer(new BigInteger(23), 5);

        // Act - Extract 2 leading bits (should get 10 = 2, leaving 111 = 7)
        var extracted = buffer.ExtractLeadingBits(2);

        // Assert
        extracted.Should().Be(new BigInteger(2)); // 10 in binary
        buffer.BitLength.Should().Be(3);
        buffer.Data.Should().Be(new BigInteger(7)); // 111 in binary

        Log($"Extracted 2 leading bits: {extracted}, remaining: {buffer.Data} ({buffer.BitLength} bits)");
    }

    [Fact]
    public void PeekTrailingBits_ShouldNotModifyBuffer()
    {
        // Arrange - Start with 23 (binary: 10111, 5 bits)
        var buffer = new BitBuffer(new BigInteger(23), 5);
        var originalData = buffer.Data;
        var originalLength = buffer.BitLength;

        // Act - Peek at 2 trailing bits
        var peeked = buffer.PeekTrailingBits(2);

        // Assert
        peeked.Should().Be(new BigInteger(3)); // 11 in binary
        buffer.BitLength.Should().Be(originalLength); // Should not change
        buffer.Data.Should().Be(originalData); // Should not change

        Log($"Peeked at 2 trailing bits: {peeked}, buffer unchanged: {buffer.Data} ({buffer.BitLength} bits)");
    }

    [Fact]
    public void PeekLeadingBits_ShouldNotModifyBuffer()
    {
        // Arrange - Start with 23 (binary: 10111, 5 bits)
        var buffer = new BitBuffer(new BigInteger(23), 5);
        var originalData = buffer.Data;
        var originalLength = buffer.BitLength;

        // Act - Peek at 2 leading bits
        var peeked = buffer.PeekLeadingBits(2);

        // Assert
        peeked.Should().Be(new BigInteger(2)); // 10 in binary
        buffer.BitLength.Should().Be(originalLength); // Should not change
        buffer.Data.Should().Be(originalData); // Should not change

        Log($"Peeked at 2 leading bits: {peeked}, buffer unchanged: {buffer.Data} ({buffer.BitLength} bits)");
    }

    [Fact]
    public void ToBytes_ShouldCreateBigEndianByteArray()
    {
        // Arrange - Create buffer with 0x1234 (16 bits)
        var buffer = new BitBuffer(new BigInteger(0x1234), 16);

        // Act
        var bytes = buffer.ToBytes();

        // Assert
        bytes.Should().Equal(0x12, 0x34); // Big-endian

        Log($"Buffer 0x1234 converted to bytes: {Convert.ToHexString(bytes)}");
    }

    [Fact]
    public void ToBytes_WithSpecificByteCount_ShouldPadOrTruncate()
    {
        // Arrange - Create buffer with 0x12 (8 bits)
        var buffer = new BitBuffer(new BigInteger(0x12), 8);

        // Act - Request 3 bytes
        var bytes = buffer.ToBytes(3);

        // Assert
        bytes.Should().Equal(0x00, 0x00, 0x12); // Padded with zeros

        Log($"Buffer 0x12 converted to 3 bytes: {Convert.ToHexString(bytes)}");
    }

    [Fact]
    public void FromBytes_ShouldCreateBufferFromByteArray()
    {
        // Arrange
        var bytes = new byte[] { 0x12, 0x34 };

        // Act
        var buffer = BitBuffer.FromBytes(bytes);

        // Assert
        buffer.BitLength.Should().Be(16);
        buffer.Data.Should().Be(new BigInteger(0x1234));

        Log($"Created buffer from bytes {Convert.ToHexString(bytes)}: {buffer.Data} ({buffer.BitLength} bits)");
    }

    [Fact]
    public void FromBytes_WithBitCount_ShouldUseLimitedBits()
    {
        // Arrange
        var bytes = new byte[] { 0xFF, 0xFF }; // 16 bits of 1s

        // Act
        var buffer = BitBuffer.FromBytes(bytes, 12); // Only use 12 bits

        // Assert
        buffer.BitLength.Should().Be(12);
        buffer.Data.Should().Be(new BigInteger(0xFFF)); // 12 bits of 1s

        Log($"Created buffer from bytes with bit limit 12: {buffer.Data} ({buffer.BitLength} bits)");
    }

    [Fact]
    public void Clear_ShouldResetBuffer()
    {
        // Arrange
        var buffer = new BitBuffer(new BigInteger(0x1234), 16);

        // Act
        buffer.Clear();

        // Assert
        buffer.BitLength.Should().Be(0);
        buffer.Data.Should().Be(BigInteger.Zero);
        buffer.ToBytes().Should().BeEmpty();

        Log("Buffer cleared successfully");
    }

    [Fact]
    public void Clone_ShouldCreateIndependentCopy()
    {
        // Arrange
        var original = new BitBuffer(new BigInteger(0x1234), 16);

        // Act
        var clone = original.Clone();
        clone.AppendTrailingBits(new BigInteger(0x56), 8); // Modify clone

        // Assert
        clone.Should().NotBe(original);
        clone.Data.Should().NotBe(original.Data);
        clone.BitLength.Should().Be(24);
        original.BitLength.Should().Be(16); // Original should be unchanged

        Log($"Original: {original.Data} ({original.BitLength} bits)");
        Log($"Clone: {clone.Data} ({clone.BitLength} bits)");
    }

    [Fact]
    public void Equals_SameBuffers_ShouldBeEqual()
    {
        // Arrange
        var buffer1 = new BitBuffer(new BigInteger(0x1234), 16);
        var buffer2 = new BitBuffer(new BigInteger(0x1234), 16);

        // Act & Assert
        buffer1.Should().Be(buffer2);
        buffer1.Equals(buffer2).Should().BeTrue();
        buffer1.GetHashCode().Should().Be(buffer2.GetHashCode());

        Log("Equal buffers correctly identified as equal");
    }

    [Fact]
    public void Equals_DifferentBuffers_ShouldNotBeEqual()
    {
        // Arrange
        var buffer1 = new BitBuffer(new BigInteger(0x1234), 16);
        var buffer2 = new BitBuffer(new BigInteger(0x5678), 16);

        // Act & Assert
        buffer1.Should().NotBe(buffer2);
        buffer1.Equals(buffer2).Should().BeFalse();

        Log("Different buffers correctly identified as not equal");
    }

    [Theory]
    [InlineData(0, 0)]
    [InlineData(1, 1)]
    [InlineData(255, 8)]
    [InlineData(65535, 16)]
    public void ComplexScenario_BuildAndExtractBits(int value, int bitCount)
    {
        // Arrange
        var buffer = new BitBuffer();

        // Act - Build up bits in multiple operations
        buffer.AppendTrailingBits(new BigInteger(value), bitCount);
        buffer.AppendLeadingBits(new BigInteger(0xA), 4); // Add 1010 at the front
        buffer.AppendTrailingBits(new BigInteger(0x5), 4); // Add 0101 at the end

        // Extract and verify
        var leadingNibble = buffer.ExtractLeadingBits(4);
        var trailingNibble = buffer.ExtractTrailingBits(4);

        // Assert
        leadingNibble.Should().Be(new BigInteger(0xA));
        trailingNibble.Should().Be(new BigInteger(0x5));
        buffer.Data.Should().Be(new BigInteger(value));
        buffer.BitLength.Should().Be(bitCount);

        Log($"Complex scenario completed successfully for value {value} ({bitCount} bits)");
    }
}