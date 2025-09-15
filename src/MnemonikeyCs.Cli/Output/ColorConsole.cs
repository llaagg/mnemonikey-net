using System;
using Spectre.Console;

namespace MnemonikeyCs.Cli.Output;

/// <summary>
/// Provides colored console output utilities.
/// </summary>
public static class ColorConsole
{
    /// <summary>
    /// Writes informational text in default color.
    /// </summary>
    /// <param name="message">The message to write.</param>
    public static void WriteInfo(string message)
    {
        AnsiConsole.WriteLine(message);
    }

    /// <summary>
    /// Writes success text in green.
    /// </summary>
    /// <param name="message">The message to write.</param>
    public static void WriteSuccess(string message)
    {
        AnsiConsole.MarkupLine($"[green]{Markup.Escape(message)}[/]");
    }

    /// <summary>
    /// Writes warning text in yellow.
    /// </summary>
    /// <param name="message">The message to write.</param>
    public static void WriteWarning(string message)
    {
        AnsiConsole.MarkupLine($"[yellow]{Markup.Escape(message)}[/]");
    }

    /// <summary>
    /// Writes error text in red.
    /// </summary>
    /// <param name="message">The message to write.</param>
    public static void WriteError(string message)
    {
        AnsiConsole.MarkupLine($"[red]{Markup.Escape(message)}[/]");
    }

    /// <summary>
    /// Writes highlighted text in cyan.
    /// </summary>
    /// <param name="message">The message to write.</param>
    public static void WriteHighlight(string message)
    {
        AnsiConsole.MarkupLine($"[cyan]{Markup.Escape(message)}[/]");
    }

    /// <summary>
    /// Writes muted text in gray.
    /// </summary>
    /// <param name="message">The message to write.</param>
    public static void WriteMuted(string message)
    {
        AnsiConsole.MarkupLine($"[grey]{Markup.Escape(message)}[/]");
    }

    /// <summary>
    /// Writes a blank line.
    /// </summary>
    public static void WriteLine()
    {
        AnsiConsole.WriteLine();
    }

    /// <summary>
    /// Writes a rule/separator line.
    /// </summary>
    /// <param name="title">Optional title for the rule.</param>
    public static void WriteRule(string? title = null)
    {
        if (string.IsNullOrEmpty(title))
        {
            AnsiConsole.Write(new Rule());
        }
        else
        {
            AnsiConsole.Write(new Rule(title));
        }
    }

    /// <summary>
    /// Writes text with a specific color.
    /// </summary>
    /// <param name="message">The message to write.</param>
    /// <param name="color">The color to use.</param>
    public static void WriteColored(string message, Color color)
    {
        AnsiConsole.MarkupLine($"[{color}]{Markup.Escape(message)}[/]");
    }

    /// <summary>
    /// Prompts the user for a yes/no response.
    /// </summary>
    /// <param name="prompt">The prompt message.</param>
    /// <param name="defaultValue">The default value if user just presses Enter.</param>
    /// <returns>True if yes, false if no.</returns>
    public static bool Confirm(string prompt, bool defaultValue = false)
    {
        return AnsiConsole.Confirm(prompt, defaultValue);
    }

    /// <summary>
    /// Prompts the user for text input.
    /// </summary>
    /// <param name="prompt">The prompt message.</param>
    /// <param name="allowEmpty">Whether to allow empty input.</param>
    /// <returns>The user's input.</returns>
    public static string Prompt(string prompt, bool allowEmpty = false)
    {
        var textPrompt = new TextPrompt<string>(prompt);
        if (!allowEmpty)
        {
            textPrompt.Validate(input => !string.IsNullOrWhiteSpace(input) 
                ? ValidationResult.Success() 
                : ValidationResult.Error("Input cannot be empty"));
        }
        return textPrompt.ShowDefaultValue(false).Show(AnsiConsole.Console);
    }

    /// <summary>
    /// Prompts the user for secure text input (password).
    /// </summary>
    /// <param name="prompt">The prompt message.</param>
    /// <param name="allowEmpty">Whether to allow empty input.</param>
    /// <returns>The user's input.</returns>
    public static string PromptSecret(string prompt, bool allowEmpty = false)
    {
        var textPrompt = new TextPrompt<string>(prompt).Secret();
        if (!allowEmpty)
        {
            textPrompt.Validate(input => !string.IsNullOrWhiteSpace(input) 
                ? ValidationResult.Success() 
                : ValidationResult.Error("Input cannot be empty"));
        }
        return textPrompt.ShowDefaultValue(false).Show(AnsiConsole.Console);
    }

    /// <summary>
    /// Shows a progress bar while executing an action.
    /// </summary>
    /// <param name="action">The action to execute with progress reporting.</param>
    /// <param name="description">Description of the operation.</param>
    public static void WithProgress(Action<IProgress<string>> action, string description = "Working...")
    {
        AnsiConsole.Progress()
            .Start(ctx =>
            {
                var task = ctx.AddTask(description);
                task.IsIndeterminate = true;
                
                var progress = new Progress<string>(status =>
                {
                    task.Description = status;
                });
                
                action(progress);
                task.StopTask();
            });
    }

    /// <summary>
    /// Shows a progress bar while executing an async action.
    /// </summary>
    /// <param name="action">The async action to execute with progress reporting.</param>
    /// <param name="description">Description of the operation.</param>
    /// <returns>Task representing the operation.</returns>
    public static async Task WithProgressAsync(Func<IProgress<string>, Task> action, string description = "Working...")
    {
        await AnsiConsole.Progress()
            .StartAsync(async ctx =>
            {
                var task = ctx.AddTask(description);
                task.IsIndeterminate = true;
                
                var progress = new Progress<string>(status =>
                {
                    task.Description = status;
                });
                
                await action(progress);
                task.StopTask();
            });
    }
}