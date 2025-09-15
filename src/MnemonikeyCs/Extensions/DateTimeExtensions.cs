using System;
using MnemonikeyCs.Core;

namespace MnemonikeyCs.Extensions;

/// <summary>
/// Extension methods for DateTime operations in the mnemonikey context.
/// </summary>
public static class DateTimeExtensions
{
    /// <summary>
    /// Converts a DateTime to a mnemonikey creation offset.
    /// </summary>
    /// <param name="creationTime">The creation time to convert.</param>
    /// <returns>The creation offset in seconds from the mnemonikey epoch.</returns>
    /// <exception cref="ArgumentException">Thrown when the creation time is outside the valid range.</exception>
    public static uint ToCreationOffset(this DateTime creationTime)
    {
        if (creationTime.Kind != DateTimeKind.Utc)
        {
            creationTime = creationTime.ToUniversalTime();
        }

        if (creationTime < Constants.EpochStart)
        {
            throw new ArgumentException($"Creation time cannot be before {Constants.EpochStart:yyyy-MM-dd HH:mm:ss} UTC", nameof(creationTime));
        }

        if (creationTime > Constants.MaxCreationTime)
        {
            throw new ArgumentException($"Creation time cannot be after {Constants.MaxCreationTime:yyyy-MM-dd HH:mm:ss} UTC", nameof(creationTime));
        }

        var offset = creationTime - Constants.EpochStart;
        return (uint)offset.TotalSeconds;
    }

    /// <summary>
    /// Converts a mnemonikey creation offset to a DateTime.
    /// </summary>
    /// <param name="creationOffset">The creation offset in seconds from the mnemonikey epoch.</param>
    /// <returns>The DateTime representing the creation time.</returns>
    public static DateTime FromCreationOffset(uint creationOffset)
    {
        return Constants.EpochStart.AddSeconds(creationOffset);
    }

    /// <summary>
    /// Floors a DateTime to the nearest epoch increment (1 second) after the mnemonikey epoch.
    /// </summary>
    /// <param name="dateTime">The DateTime to floor.</param>
    /// <returns>The floored DateTime.</returns>
    public static DateTime FloorToEpochIncrement(this DateTime dateTime)
    {
        if (dateTime.Kind != DateTimeKind.Utc)
        {
            dateTime = dateTime.ToUniversalTime();
        }

        if (dateTime < Constants.EpochStart)
        {
            return Constants.EpochStart;
        }

        var offset = dateTime - Constants.EpochStart;
        var flooredOffset = TimeSpan.FromSeconds(Math.Floor(offset.TotalSeconds));
        return Constants.EpochStart.Add(flooredOffset);
    }

    /// <summary>
    /// Checks if a DateTime is within the valid range for mnemonikey operations.
    /// </summary>
    /// <param name="dateTime">The DateTime to check.</param>
    /// <returns>true if the DateTime is valid; otherwise, false.</returns>
    public static bool IsValidCreationTime(this DateTime dateTime)
    {
        if (dateTime.Kind != DateTimeKind.Utc)
        {
            dateTime = dateTime.ToUniversalTime();
        }

        return dateTime >= Constants.EpochStart && dateTime <= Constants.MaxCreationTime;
    }

    /// <summary>
    /// Converts a DateTime to a Unix timestamp (seconds since Unix epoch).
    /// </summary>
    /// <param name="dateTime">The DateTime to convert.</param>
    /// <returns>The Unix timestamp.</returns>
    public static uint ToUnixTimestamp(this DateTime dateTime)
    {
        if (dateTime.Kind != DateTimeKind.Utc)
        {
            dateTime = dateTime.ToUniversalTime();
        }

        return (uint)((DateTimeOffset)dateTime).ToUnixTimeSeconds();
    }

    /// <summary>
    /// Converts a Unix timestamp to a DateTime.
    /// </summary>
    /// <param name="unixTimestamp">The Unix timestamp (seconds since Unix epoch).</param>
    /// <returns>The DateTime in UTC.</returns>
    public static DateTime FromUnixTimestamp(uint unixTimestamp)
    {
        return DateTimeOffset.FromUnixTimeSeconds(unixTimestamp).UtcDateTime;
    }

    /// <summary>
    /// Gets the number of seconds between two DateTimes.
    /// </summary>
    /// <param name="start">The start DateTime.</param>
    /// <param name="end">The end DateTime.</param>
    /// <returns>The number of seconds between the DateTimes.</returns>
    public static double GetSecondsBetween(this DateTime start, DateTime end)
    {
        return (end - start).TotalSeconds;
    }

    /// <summary>
    /// Adds a duration specified in seconds to a DateTime.
    /// </summary>
    /// <param name="dateTime">The base DateTime.</param>
    /// <param name="seconds">The number of seconds to add.</param>
    /// <returns>A new DateTime with the duration added.</returns>
    public static DateTime AddSeconds(this DateTime dateTime, uint seconds)
    {
        return dateTime.AddSeconds((double)seconds);
    }

    /// <summary>
    /// Parses a duration string and returns the corresponding TimeSpan.
    /// Supports formats like "1y", "2m", "30d", "12h", "45min", "30s".
    /// </summary>
    /// <param name="duration">The duration string to parse.</param>
    /// <returns>The parsed TimeSpan.</returns>
    /// <exception cref="ArgumentException">Thrown when the duration format is invalid.</exception>
    public static TimeSpan ParseDuration(string duration)
    {
        if (string.IsNullOrWhiteSpace(duration))
        {
            throw new ArgumentException("Duration cannot be null or empty", nameof(duration));
        }

        duration = duration.Trim().ToLowerInvariant();

        // Handle common suffixes
        if (duration.EndsWith("y") || duration.EndsWith("year") || duration.EndsWith("years"))
        {
            var value = ExtractNumericPart(duration);
            return TimeSpan.FromDays(value * 365);
        }
        
        if (duration.EndsWith("mo") || duration.EndsWith("month") || duration.EndsWith("months"))
        {
            var value = ExtractNumericPart(duration);
            return TimeSpan.FromDays(value * 30);
        }
        
        if (duration.EndsWith("w") || duration.EndsWith("week") || duration.EndsWith("weeks"))
        {
            var value = ExtractNumericPart(duration);
            return TimeSpan.FromDays(value * 7);
        }
        
        if (duration.EndsWith("d") || duration.EndsWith("day") || duration.EndsWith("days"))
        {
            var value = ExtractNumericPart(duration);
            return TimeSpan.FromDays(value);
        }
        
        if (duration.EndsWith("h") || duration.EndsWith("hour") || duration.EndsWith("hours"))
        {
            var value = ExtractNumericPart(duration);
            return TimeSpan.FromHours(value);
        }
        
        if (duration.EndsWith("min") || duration.EndsWith("minute") || duration.EndsWith("minutes"))
        {
            var value = ExtractNumericPart(duration);
            return TimeSpan.FromMinutes(value);
        }
        
        if (duration.EndsWith("s") || duration.EndsWith("sec") || duration.EndsWith("second") || duration.EndsWith("seconds"))
        {
            var value = ExtractNumericPart(duration);
            return TimeSpan.FromSeconds(value);
        }

        // Try parsing as a pure number (assume seconds)
        if (double.TryParse(duration, out var seconds))
        {
            return TimeSpan.FromSeconds(seconds);
        }

        throw new ArgumentException($"Invalid duration format: {duration}", nameof(duration));
    }

    private static double ExtractNumericPart(string duration)
    {
        var numericPart = "";
        foreach (var c in duration)
        {
            if (char.IsDigit(c) || c == '.' || c == '-')
            {
                numericPart += c;
            }
            else
            {
                break;
            }
        }

        if (double.TryParse(numericPart, out var value))
        {
            return value;
        }

        throw new ArgumentException($"Cannot extract numeric value from duration: {duration}");
    }
}