using System;
using System.Text.RegularExpressions;

namespace MnemonikeyCs.Cli.Validation;

/// <summary>
/// Provides email address validation functionality.
/// </summary>
public static class EmailValidator
{
    private static readonly Regex EmailRegex = new(
        @"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    /// <summary>
    /// Validates an email address format.
    /// </summary>
    /// <param name="email">The email address to validate.</param>
    /// <returns>A validation result.</returns>
    public static ValidationResult ValidateEmail(string? email)
    {
        if (string.IsNullOrWhiteSpace(email))
        {
            return ValidationResult.Error("Email address cannot be empty.");
        }

        var trimmedEmail = email.Trim();

        // Check length (RFC 5321 limit)
        if (trimmedEmail.Length > 320)
        {
            return ValidationResult.Error("Email address is too long (maximum 320 characters).");
        }

        // Check minimum length
        if (trimmedEmail.Length < 3)
        {
            return ValidationResult.Error("Email address is too short.");
        }

        // Check for basic format requirements
        if (!trimmedEmail.Contains('@'))
        {
            return ValidationResult.Error("Email address must contain an @ symbol.");
        }

        var parts = trimmedEmail.Split('@');
        if (parts.Length != 2)
        {
            return ValidationResult.Error("Email address must contain exactly one @ symbol.");
        }

        var localPart = parts[0];
        var domainPart = parts[1];

        // Validate local part
        var localValidation = ValidateLocalPart(localPart);
        if (!localValidation.IsValid)
        {
            return localValidation;
        }

        // Validate domain part
        var domainValidation = ValidateDomainPart(domainPart);
        if (!domainValidation.IsValid)
        {
            return domainValidation;
        }

        // Validate full email with regex
        if (!EmailRegex.IsMatch(trimmedEmail))
        {
            return ValidationResult.Error("Email address format is invalid.");
        }

        return ValidationResult.Success();
    }

    /// <summary>
    /// Checks if an email address is valid.
    /// </summary>
    /// <param name="email">The email address to check.</param>
    /// <returns>True if valid, false otherwise.</returns>
    public static bool IsValidEmail(string? email)
    {
        return ValidateEmail(email).IsValid;
    }

    /// <summary>
    /// Normalizes an email address (trims whitespace and converts to lowercase).
    /// </summary>
    /// <param name="email">The email address to normalize.</param>
    /// <returns>The normalized email address.</returns>
    public static string NormalizeEmail(string email)
    {
        if (string.IsNullOrWhiteSpace(email))
        {
            return string.Empty;
        }

        return email.Trim().ToLowerInvariant();
    }

    /// <summary>
    /// Suggests corrections for common email typos.
    /// </summary>
    /// <param name="email">The potentially misspelled email.</param>
    /// <returns>A suggested correction, or null if no suggestion available.</returns>
    public static string? SuggestCorrection(string email)
    {
        if (string.IsNullOrWhiteSpace(email))
        {
            return null;
        }

        var normalized = email.Trim().ToLowerInvariant();

        // Common domain typos
        var commonDomains = new Dictionary<string, string[]>
        {
            ["gmail.com"] = new[] { "gmai.com", "gmial.com", "gmail.co", "gmai.co", "gamil.com" },
            ["hotmail.com"] = new[] { "hotmai.com", "hotmial.com", "hotmail.co", "hotmial.co" },
            ["yahoo.com"] = new[] { "yahoo.co", "yaho.com", "yahooo.com", "yhoo.com" },
            ["outlook.com"] = new[] { "outlook.co", "outlok.com", "outloook.com" },
            ["icloud.com"] = new[] { "icloud.co", "icoud.com", "icloud.com" }
        };

        if (!normalized.Contains('@'))
        {
            return null;
        }

        var parts = normalized.Split('@');
        if (parts.Length != 2)
        {
            return null;
        }

        var domain = parts[1];

        foreach (var correctDomain in commonDomains.Keys)
        {
            if (commonDomains[correctDomain].Contains(domain))
            {
                return $"{parts[0]}@{correctDomain}";
            }
        }

        return null;
    }

    /// <summary>
    /// Validates the local part (before @) of an email address.
    /// </summary>
    /// <param name="localPart">The local part to validate.</param>
    /// <returns>A validation result.</returns>
    private static ValidationResult ValidateLocalPart(string localPart)
    {
        if (string.IsNullOrEmpty(localPart))
        {
            return ValidationResult.Error("Local part of email address cannot be empty.");
        }

        // RFC 5321 limit for local part is 64 characters
        if (localPart.Length > 64)
        {
            return ValidationResult.Error("Local part of email address is too long (maximum 64 characters).");
        }

        // Check for leading/trailing dots
        if (localPart.StartsWith('.') || localPart.EndsWith('.'))
        {
            return ValidationResult.Error("Local part cannot start or end with a dot.");
        }

        // Check for consecutive dots
        if (localPart.Contains(".."))
        {
            return ValidationResult.Error("Local part cannot contain consecutive dots.");
        }

        return ValidationResult.Success();
    }

    /// <summary>
    /// Validates the domain part (after @) of an email address.
    /// </summary>
    /// <param name="domainPart">The domain part to validate.</param>
    /// <returns>A validation result.</returns>
    private static ValidationResult ValidateDomainPart(string domainPart)
    {
        if (string.IsNullOrEmpty(domainPart))
        {
            return ValidationResult.Error("Domain part of email address cannot be empty.");
        }

        // RFC 5321 limit for domain part is 255 characters
        if (domainPart.Length > 255)
        {
            return ValidationResult.Error("Domain part of email address is too long (maximum 255 characters).");
        }

        // Check for leading/trailing dots or hyphens
        if (domainPart.StartsWith('.') || domainPart.EndsWith('.') ||
            domainPart.StartsWith('-') || domainPart.EndsWith('-'))
        {
            return ValidationResult.Error("Domain part cannot start or end with a dot or hyphen.");
        }

        // Must contain at least one dot (TLD requirement)
        if (!domainPart.Contains('.'))
        {
            return ValidationResult.Error("Domain part must contain at least one dot (for TLD).");
        }

        // Check for consecutive dots
        if (domainPart.Contains(".."))
        {
            return ValidationResult.Error("Domain part cannot contain consecutive dots.");
        }

        // Validate domain labels
        var labels = domainPart.Split('.');
        foreach (var label in labels)
        {
            if (string.IsNullOrEmpty(label))
            {
                return ValidationResult.Error("Domain labels cannot be empty.");
            }

            if (label.Length > 63)
            {
                return ValidationResult.Error("Domain labels cannot be longer than 63 characters.");
            }

            if (label.StartsWith('-') || label.EndsWith('-'))
            {
                return ValidationResult.Error("Domain labels cannot start or end with a hyphen.");
            }
        }

        return ValidationResult.Success();
    }
}

/// <summary>
/// Represents the result of a validation operation.
/// </summary>
public class ValidationResult
{
    /// <summary>
    /// Gets whether the validation was successful.
    /// </summary>
    public bool IsValid { get; private set; }

    /// <summary>
    /// Gets the error message if validation failed.
    /// </summary>
    public string? ErrorMessage { get; private set; }

    /// <summary>
    /// Creates a successful validation result.
    /// </summary>
    /// <returns>A successful validation result.</returns>
    public static ValidationResult Success() => new() { IsValid = true };

    /// <summary>
    /// Creates a failed validation result with an error message.
    /// </summary>
    /// <param name="errorMessage">The error message.</param>
    /// <returns>A failed validation result.</returns>
    public static ValidationResult Error(string errorMessage) => new() 
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
        return IsValid ? "Valid" : $"Invalid: {ErrorMessage}";
    }
}