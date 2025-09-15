using System;
using System.Threading.Tasks;
using Spectre.Console;

namespace MnemonikeyCs.Cli.Output;

/// <summary>
/// Provides progress indication for long-running operations.
/// </summary>
public static class ProgressIndicator
{
    /// <summary>
    /// Shows a spinner while executing a synchronous operation.
    /// </summary>
    /// <param name="action">The action to execute.</param>
    /// <param name="description">Description of the operation.</param>
    public static void WithSpinner(Action action, string description = "Working...")
    {
        AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .Start(description, ctx =>
            {
                action();
            });
    }

    /// <summary>
    /// Shows a spinner while executing an asynchronous operation.
    /// </summary>
    /// <param name="action">The async action to execute.</param>
    /// <param name="description">Description of the operation.</param>
    /// <returns>Task representing the operation.</returns>
    public static async Task WithSpinnerAsync(Func<Task> action, string description = "Working...")
    {
        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .StartAsync(description, async ctx =>
            {
                await action();
            });
    }

    /// <summary>
    /// Shows a spinner while executing a synchronous operation with status updates.
    /// </summary>
    /// <param name="action">The action to execute with status updates.</param>
    /// <param name="description">Initial description of the operation.</param>
    public static void WithSpinner(Action<IProgress<string>> action, string description = "Working...")
    {
        AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .Start(description, ctx =>
            {
                var progress = new Progress<string>(status =>
                {
                    ctx.Status(status);
                });
                
                action(progress);
            });
    }

    /// <summary>
    /// Shows a spinner while executing an asynchronous operation with status updates.
    /// </summary>
    /// <param name="action">The async action to execute with status updates.</param>
    /// <param name="description">Initial description of the operation.</param>
    /// <returns>Task representing the operation.</returns>
    public static async Task WithSpinnerAsync(Func<IProgress<string>, Task> action, string description = "Working...")
    {
        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .StartAsync(description, async ctx =>
            {
                var progress = new Progress<string>(status =>
                {
                    ctx.Status(status);
                });
                
                await action(progress);
            });
    }

    /// <summary>
    /// Shows a determinate progress bar.
    /// </summary>
    /// <param name="action">The action to execute with progress updates.</param>
    /// <param name="description">Description of the operation.</param>
    /// <param name="maxValue">Maximum value for the progress bar.</param>
    public static void WithProgressBar(Action<IProgress<int>> action, string description = "Processing...", int maxValue = 100)
    {
        AnsiConsole.Progress()
            .Start(ctx =>
            {
                var task = ctx.AddTask(description, maxValue: maxValue);
                
                var progress = new Progress<int>(value =>
                {
                    task.Value = value;
                });
                
                action(progress);
                task.Value = maxValue;
            });
    }

    /// <summary>
    /// Shows a determinate progress bar for async operations.
    /// </summary>
    /// <param name="action">The async action to execute with progress updates.</param>
    /// <param name="description">Description of the operation.</param>
    /// <param name="maxValue">Maximum value for the progress bar.</param>
    /// <returns>Task representing the operation.</returns>
    public static async Task WithProgressBarAsync(Func<IProgress<int>, Task> action, string description = "Processing...", int maxValue = 100)
    {
        await AnsiConsole.Progress()
            .StartAsync(async ctx =>
            {
                var task = ctx.AddTask(description, maxValue: maxValue);
                
                var progress = new Progress<int>(value =>
                {
                    task.Value = value;
                });
                
                await action(progress);
                task.Value = maxValue;
            });
    }

    /// <summary>
    /// Shows multiple progress tasks simultaneously.
    /// </summary>
    /// <param name="tasks">Collection of tasks to execute.</param>
    public static void WithMultipleProgress(IEnumerable<ProgressTask> tasks)
    {
        AnsiConsole.Progress()
            .Columns(new TaskDescriptionColumn(),
                    new ProgressBarColumn(),
                    new PercentageColumn(),
                    new SpinnerColumn())
            .Start(ctx =>
            {
                var progressTasks = new Dictionary<string, Spectre.Console.ProgressTask>();
                
                foreach (var task in tasks)
                {
                    var progressTask = ctx.AddTask(task.Description, maxValue: task.MaxValue);
                    progressTasks[task.Id] = progressTask;
                    
                    Task.Run(() =>
                    {
                        var progress = new Progress<int>(value =>
                        {
                            progressTask.Value = value;
                        });
                        
                        task.Action(progress);
                        progressTask.Value = task.MaxValue;
                    });
                }
                
                // Wait for all tasks to complete
                while (progressTasks.Values.Any(t => t.Value < t.MaxValue))
                {
                    Thread.Sleep(50);
                }
            });
    }

    /// <summary>
    /// Shows an indeterminate progress indicator for key generation operations.
    /// </summary>
    /// <param name="action">The action to execute.</param>
    /// <param name="keyType">Type of key being generated (for display purposes).</param>
    public static void WithKeyGenerationProgress(Action action, string keyType = "PGP key")
    {
        WithSpinner(progress =>
        {
            progress.Report($"Generating {keyType}...");
            Thread.Sleep(100); // Small delay to show the initial message
            
            progress.Report($"Deriving cryptographic material...");
            action();
            
            progress.Report($"{keyType} generation complete");
        }, $"Generating {keyType}...");
    }

    /// <summary>
    /// Shows an indeterminate progress indicator for key generation operations (async).
    /// </summary>
    /// <param name="action">The async action to execute.</param>
    /// <param name="keyType">Type of key being generated (for display purposes).</param>
    /// <returns>Task representing the operation.</returns>
    public static async Task WithKeyGenerationProgressAsync(Func<Task> action, string keyType = "PGP key")
    {
        await WithSpinnerAsync(async progress =>
        {
            progress.Report($"Generating {keyType}...");
            await Task.Delay(100); // Small delay to show the initial message
            
            progress.Report($"Deriving cryptographic material...");
            await action();
            
            progress.Report($"{keyType} generation complete");
        }, $"Generating {keyType}...");
    }
}

/// <summary>
/// Represents a task for multi-progress operations.
/// </summary>
public class ProgressTask
{
    /// <summary>
    /// Gets or sets the unique identifier for the task.
    /// </summary>
    public string Id { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the description of the task.
    /// </summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the maximum value for progress.
    /// </summary>
    public int MaxValue { get; set; } = 100;

    /// <summary>
    /// Gets or sets the action to execute with progress reporting.
    /// </summary>
    public Action<IProgress<int>> Action { get; set; } = _ => { };
}