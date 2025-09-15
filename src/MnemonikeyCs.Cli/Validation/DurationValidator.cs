using System;
using System.Globalization;
using System.Text.RegularExpressions;

namespace MnemonikeyCs.Cli.Validation;

/// <summary>
/// Provides duration validation and parsing functionality for TTL values.
/// </summary>
public static class DurationValidator
{
    private static readonly Regex DurationRegex = new(
        @"^(\d+)([ymdh])$",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    /// <summary>
    /// Validates and parses a duration string (e.g., "1y", "6m", "30d").
    /// </summary>
    /// <param name="duration">The duration string to validate.</param>
    /// <returns>A validation result with the parsed TimeSpan if successful.</returns>
    public static DurationValidationResult ValidateDuration(string? duration)
    {
        if (string.IsNullOrWhiteSpace(duration))
        {
            return DurationValidationResult.Error("Duration cannot be empty.");
        }

        var trimmed = duration.Trim().ToLowerInvariant();

        // Check basic format
        var match = DurationRegex.Match(trimmed);
        if (!match.Success)
        {
            return DurationValidationResult.Error(
                "Duration format is invalid. Use format like '1y', '6m', '30d', or '24h'.");
        }

        // Parse number and unit
        if (!int.TryParse(match.Groups[1].Value, out var value))
        {
            return DurationValidationResult.Error("Duration value must be a valid integer.");
        }

        if (value <= 0)
        {
            return DurationValidationResult.Error("Duration value must be positive.");
        }

        var unit = match.Groups[2].Value;

        // Convert to TimeSpan based on unit
        TimeSpan timeSpan;
        try
        {
            timeSpan = unit switch
            {
                "y" => TimeSpan.FromDays(value * 365), // Approximate year
                "m" => TimeSpan.FromDays(value * 30),  // Approximate month
                "d" => TimeSpan.FromDays(value),
                "h" => TimeSpan.FromHours(value),
                _ => throw new ArgumentException($"Unknown unit: {unit}")
            };
        }
        catch (OverflowException)
        {
            return DurationValidationResult.Error("Duration value is too large.");
        }
        catch (ArgumentException ex)
        {
            return DurationValidationResult.Error(ex.Message);
        }

        // Validate reasonable bounds
        var validationResult = ValidateReasonableDuration(timeSpan, unit);
        if (!validationResult.IsValid)
        {
            return DurationValidationResult.Error(validationResult.ErrorMessage!);
        }

        return DurationValidationResult.Success(timeSpan);
    }

    /// <summary>
    /// Checks if a duration string is valid.
    /// </summary>
    /// <param name="duration">The duration string to check.</param>
    /// <returns>True if valid, false otherwise.</returns>
    public static bool IsValidDuration(string? duration)
    {
        return ValidateDuration(duration).IsValid;
    }

    /// <summary>
    /// Parses a duration string to a TimeSpan.
    /// </summary>
    /// <param name="duration">The duration string to parse.</param>
    /// <returns>The parsed TimeSpan.</returns>
    /// <exception cref="ArgumentException">Thrown when the duration string is invalid.</exception>
    public static TimeSpan ParseDuration(string duration)
    {
        var result = ValidateDuration(duration);
        if (!result.IsValid)
        {
            throw new ArgumentException(result.ErrorMessage, nameof(duration));
        }

        return result.Duration!.Value;
    }

    /// <summary>
    /// Converts a TimeSpan to a human-readable duration string.
    /// </summary>
    /// <param name="duration">The TimeSpan to convert.</param>
    /// <returns>A human-readable duration string.</returns>
    public static string FormatDuration(TimeSpan duration)
    {
        if (duration.TotalDays >= 365)
        {
            var years = (int)(duration.TotalDays / 365);
            var remainingDays = (int)(duration.TotalDays % 365);
            
            if (remainingDays == 0)
            {
                return years == 1 ? "1 year" : $"{years} years";
            }
            else
            {
                var yearPart = years == 1 ? "1 year" : $"{years} years";
                var dayPart = remainingDays == 1 ? "1 day" : $"{remainingDays} days";
                return $"{yearPart}, {dayPart}";
            }
        }

        if (duration.TotalDays >= 30)
        {
            var months = (int)(duration.TotalDays / 30);
            var remainingDays = (int)(duration.TotalDays % 30);
            
            if (remainingDays == 0)
            {
                return months == 1 ? "1 month" : $"{months} months";
            }
            else
            {
                var monthPart = months == 1 ? "1 month" : $"{months} months";
                var dayPart = remainingDays == 1 ? "1 day" : $"{remainingDays} days";
                return $"{monthPart}, {dayPart}";
            }
        }

        if (duration.TotalDays >= 1)
        {
            var days = (int)duration.TotalDays;
            var remainingHours = duration.Hours;
            
            if (remainingHours == 0)
            {
                return days == 1 ? "1 day" : $"{days} days";
            }
            else
            {
                var dayPart = days == 1 ? "1 day" : $"{days} days";
                var hourPart = remainingHours == 1 ? "1 hour" : $"{remainingHours} hours";
                return $"{dayPart}, {hourPart}";
            }
        }

        if (duration.TotalHours >= 1)
        {
            var hours = (int)duration.TotalHours;
            return hours == 1 ? "1 hour" : $"{hours} hours";
        }

        var minutes = (int)duration.TotalMinutes;
        return minutes == 1 ? "1 minute" : $"{minutes} minutes";
    }

    /// <summary>
    /// Suggests common duration values.
    /// </summary>
    /// <returns>An array of suggested duration strings.</returns>
    public static string[] GetSuggestedDurations()
    {
        return new[]
        {
            "1y",   // 1 year
            "2y",   // 2 years
            "5y",   // 5 years
            "6m",   // 6 months
            "1m",   // 1 month
            "30d",  // 30 days
            "7d",   // 1 week
            "1d",   // 1 day
            "12h",  // 12 hours
            "1h"    // 1 hour
        };
    }

    /// <summary>
    /// Gets examples of valid duration formats.
    /// </summary>
    /// <returns>An array of example duration strings with descriptions.</returns>
    public static (string Duration, string Description)[] GetExamples()
    {
        return new[]
        {
            ("1y", "1 year"),
            ("2y", "2 years"),
            ("6m", "6 months"),
            ("30d", "30 days"),
            ("24h", "24 hours")
        };
    }

    /// <summary>
    /// Validates that a duration is within reasonable bounds for PGP key expiration.
    /// </summary>
    /// <param name="duration">The duration to validate.</param>
    /// <param name="unit">The unit used in the original input.</param>
    /// <returns>A validation result.</returns>
    private static ValidationResult ValidateReasonableDuration(TimeSpan duration, string unit)
    {
        // Minimum duration: 1 hour
        if (duration < TimeSpan.FromHours(1))
        {
            return ValidationResult.Error("Duration must be at least 1 hour.");
        }

        // Maximum duration: 50 years (arbitrary but reasonable limit)
        if (duration > TimeSpan.FromDays(50 * 365))
        {
            return ValidationResult.Error("Duration cannot exceed 50 years.");
        }

        // Unit-specific validations
        switch (unit)
        {
            case "y":
                if (duration.TotalDays > 50 * 365)
                {
                    return ValidationResult.Error("Years cannot exceed 50.");
                }
                break;

            case "m":
                if (duration.TotalDays > 50 * 365)
                {
                    return ValidationResult.Error("Months cannot exceed 600 (50 years).");
                }
                break;

            case "d":
                if (duration.TotalDays > 50 * 365)
                {
                    return ValidationResult.Error("Days cannot exceed 18250 (50 years).");
                }
                break;

            case "h":
                if (duration.TotalDays > 365)
                {
                    return ValidationResult.Error("Hours cannot exceed 8760 (1 year).");
                }
                break;
        }

        return ValidationResult.Success();
    }
}

/// <summary>
/// Represents the result of a duration validation operation.
/// </summary>
public class DurationValidationResult
{
    /// <summary>
    /// Gets whether the validation was successful.
    /// </summary>
    public bool IsValid { get; private set; }

    /// <summary>
    /// Gets the parsed duration if validation was successful.
    /// </summary>
    public TimeSpan? Duration { get; private set; }

    /// <summary>
    /// Gets the error message if validation failed.
    /// </summary>
    public string? ErrorMessage { get; private set; }

    /// <summary>
    /// Creates a successful validation result with a parsed duration.
    /// </summary>
    /// <param name="duration">The parsed duration.</param>
    /// <returns>A successful validation result.</returns>
    public static DurationValidationResult Success(TimeSpan duration) => new() 
    { 
        IsValid = true, 
        Duration = duration 
    };

    /// <summary>
    /// Creates a failed validation result with an error message.
    /// </summary>
    /// <param name="errorMessage">The error message.</param>
    /// <returns>A failed validation result.</returns>
    public static DurationValidationResult Error(string errorMessage) => new() 
    { 
        IsValid = false, 
        ErrorMessage = errorMessage 
    };

    /// <summary>
    /// Returns a string representation of the validation result.
    /// </summary>
    /// <returns>A string representation.</returns>
    public override string ToString()
    {
        if (IsValid)
        {
            return $"Valid: {DurationValidator.FormatDuration(Duration!.Value)}";
        }
        else
        {
            return $"Invalid: {ErrorMessage}";
        }
    }
}