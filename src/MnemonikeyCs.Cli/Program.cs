using System;
using System.CommandLine;
using System.Threading.Tasks;
using MnemonikeyCs.Cli.Commands;
using MnemonikeyCs.Cli.Output;
using Spectre.Console;

namespace MnemonikeyCs.Cli;

/// <summary>
/// Main entry point for the MnemonikeyCs CLI application.
/// </summary>
public class Program
{
    /// <summary>
    /// Application name.
    /// </summary>
    public const string AppName = "mnemonikey-cs";
    
    /// <summary>
    /// Application version.
    /// </summary>
    public const string AppVersion = "1.0.0";
    
    /// <summary>
    /// Gets the global verbose option.
    /// </summary>
    public static Option<bool> GetVerboseOption()
    {
        return new Option<bool>(
            aliases: new[] { "--verbose", "-v" },
            description: "Enable verbose output");
    }

    /// <summary>
    /// Main entry point.
    /// </summary>
    /// <param name="args">Command line arguments.</param>
    /// <returns>Exit code.</returns>
    public static async Task<int> Main(string[] args)
    {
        try
        {
            var rootCommand = CreateRootCommand();
            return await rootCommand.InvokeAsync(args);
        }
        catch (Exception ex)
        {
            ColorConsole.WriteError($"Unhandled error: {ex.Message}");
            if (args.Contains("--verbose"))
            {
                ColorConsole.WriteError(ex.ToString());
            }
            return 1;
        }
    }

    /// <summary>
    /// Creates the root command with all subcommands and options.
    /// </summary>
    /// <returns>The configured root command.</returns>
    private static RootCommand CreateRootCommand()
    {
        var rootCommand = new RootCommand($"{AppName} - Deterministic PGP key generation from mnemonic phrases")
        {
            Name = AppName
        };

        // Global options  
        var verboseOption = GetVerboseOption();

        var versionOption = new Option<bool>(
            aliases: new[] { "--version" },
            description: "Show version information");

        rootCommand.AddGlobalOption(verboseOption);
        rootCommand.AddOption(versionOption);

        // Version handler
        rootCommand.SetHandler((bool version, bool verbose) =>
        {
            if (version)
            {
                ColorConsole.WriteInfo($"{AppName} version {AppVersion}");
                ColorConsole.WriteInfo("C# implementation of the mnemonikey library");
                ColorConsole.WriteInfo("https://github.com/your-username/mnemonikey-cs");
                Environment.Exit(0);
                return;
            }

            // Show help if no subcommand provided
            ColorConsole.WriteInfo($"{AppName} - Deterministic PGP key generation from mnemonic phrases");
            ColorConsole.WriteInfo("");
            ColorConsole.WriteInfo("Usage:");
            ColorConsole.WriteInfo($"  {AppName} <command> [options]");
            ColorConsole.WriteInfo("");
            ColorConsole.WriteInfo("Commands:");
            ColorConsole.WriteInfo("  generate    Generate a new PGP key with recovery phrase");
            ColorConsole.WriteInfo("  recover     Recover PGP key from recovery phrase");
            ColorConsole.WriteInfo("  convert     Convert between phrase formats");
            ColorConsole.WriteInfo("");
            ColorConsole.WriteInfo("Options:");
            ColorConsole.WriteInfo("  -h, --help       Show help information");
            ColorConsole.WriteInfo("  -v, --verbose    Enable verbose output");
            ColorConsole.WriteInfo("  --version        Show version information");
            ColorConsole.WriteInfo("");
            ColorConsole.WriteInfo($"Run '{AppName} <command> --help' for more information about a command.");
            Environment.Exit(0);
        }, versionOption, verboseOption);

        // Add subcommands
        rootCommand.AddCommand(new GenerateCommand());
        rootCommand.AddCommand(new RecoverCommand());
        rootCommand.AddCommand(new ConvertCommand());

        return rootCommand;
    }
}