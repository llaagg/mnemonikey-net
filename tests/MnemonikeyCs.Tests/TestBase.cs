using System;
using Xunit.Abstractions;

namespace MnemonikeyCs.Tests;

/// <summary>
/// Base class for all tests providing common functionality and setup.
/// </summary>
public abstract class TestBase
{
    /// <summary>
    /// Gets the test output helper for logging test information.
    /// </summary>
    protected ITestOutputHelper Output { get; }

    /// <summary>
    /// Initializes a new instance of the TestBase class.
    /// </summary>
    /// <param name="output">The test output helper.</param>
    protected TestBase(ITestOutputHelper output)
    {
        Output = output;
    }

    /// <summary>
    /// Logs a message to the test output.
    /// </summary>
    /// <param name="message">The message to log.</param>
    protected void Log(string message)
    {
        Output.WriteLine($"[{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss.fff}] {message}");
    }

    /// <summary>
    /// Logs a formatted message to the test output.
    /// </summary>
    /// <param name="format">The format string.</param>
    /// <param name="args">The format arguments.</param>
    protected void Log(string format, params object[] args)
    {
        Log(string.Format(format, args));
    }

    /// <summary>
    /// Creates a test seed from a hex string for reproducible tests.
    /// </summary>
    /// <param name="hex">The hex string (32 characters).</param>
    /// <returns>A Seed instance.</returns>
    protected static MnemonikeyCs.Core.Seed CreateTestSeed(string hex)
    {
        return MnemonikeyCs.Core.Seed.FromHex(hex);
    }

    /// <summary>
    /// Creates a test timestamp for reproducible tests.
    /// </summary>
    /// <param name="year">The year.</param>
    /// <param name="month">The month.</param>
    /// <param name="day">The day.</param>
    /// <param name="hour">The hour (optional).</param>
    /// <param name="minute">The minute (optional).</param>
    /// <param name="second">The second (optional).</param>
    /// <returns>A DateTime in UTC.</returns>
    protected static DateTime CreateTestTimestamp(int year, int month, int day, int hour = 0, int minute = 0, int second = 0)
    {
        return new DateTime(year, month, day, hour, minute, second, DateTimeKind.Utc);
    }

    /// <summary>
    /// Gets a test creation time that's known to be valid.
    /// </summary>
    protected static DateTime TestCreationTime => CreateTestTimestamp(2023, 6, 15, 12, 30, 45);

    /// <summary>
    /// Gets a test seed that's known to be valid.
    /// </summary>
    protected static MnemonikeyCs.Core.Seed TestSeed => CreateTestSeed("0123456789abcdef0123456789abcdef01234567");

    /// <summary>
    /// Asserts that two byte arrays are equal and logs details if they differ.
    /// </summary>
    /// <param name="expected">The expected byte array.</param>
    /// <param name="actual">The actual byte array.</param>
    /// <param name="message">Optional message for the assertion.</param>
    protected void AssertBytesEqual(byte[] expected, byte[] actual, string? message = null)
    {
        if (expected == null && actual == null)
            return;

        if (expected == null)
            throw new Xunit.Sdk.XunitException($"Expected null but got {actual?.Length} bytes. {message}");
        
        if (actual == null)
            throw new Xunit.Sdk.XunitException($"Expected {expected.Length} bytes but got null. {message}");

        if (expected.Length != actual.Length)
        {
            Log($"Length mismatch: expected {expected.Length}, actual {actual.Length}");
            Log($"Expected: {Convert.ToHexString(expected)}");
            Log($"Actual:   {Convert.ToHexString(actual)}");
            throw new Xunit.Sdk.XunitException($"Byte array length mismatch: expected {expected.Length}, actual {actual.Length}. {message}");
        }

        for (int i = 0; i < expected.Length; i++)
        {
            if (expected[i] != actual[i])
            {
                Log($"Byte mismatch at index {i}: expected 0x{expected[i]:X2}, actual 0x{actual[i]:X2}");
                Log($"Expected: {Convert.ToHexString(expected)}");
                Log($"Actual:   {Convert.ToHexString(actual)}");
                throw new Xunit.Sdk.XunitException($"Bytes differ at index {i}: expected 0x{expected[i]:X2}, actual 0x{actual[i]:X2}. {message}");
            }
        }

        Log($"Byte arrays match ({expected.Length} bytes)");
    }

    /// <summary>
    /// Asserts that a condition is true and logs the condition if false.
    /// </summary>
    /// <param name="condition">The condition to check.</param>
    /// <param name="message">The message to display if the condition is false.</param>
    protected void AssertTrue(bool condition, string message)
    {
        if (!condition)
        {
            Log($"Assertion failed: {message}");
            throw new Xunit.Sdk.XunitException(message);
        }
    }

    /// <summary>
    /// Asserts that a condition is false and logs the condition if true.
    /// </summary>
    /// <param name="condition">The condition to check.</param>
    /// <param name="message">The message to display if the condition is true.</param>
    protected void AssertFalse(bool condition, string message)
    {
        if (condition)
        {
            Log($"Assertion failed: {message}");
            throw new Xunit.Sdk.XunitException(message);
        }
    }
}