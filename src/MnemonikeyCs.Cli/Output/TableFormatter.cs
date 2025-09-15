using System;
using System.Collections.Generic;
using MnemonikeyCs.Pgp;
using MnemonikeyCs.Pgp.Keys;
using Spectre.Console;

namespace MnemonikeyCs.Cli.Output;

/// <summary>
/// Provides table formatting utilities for displaying key information.
/// </summary>
public static class TableFormatter
{
    /// <summary>
    /// Displays key set information in a formatted table.
    /// </summary>
    /// <param name="keySet">The key set to display.</param>
    /// <param name="title">Optional title for the table.</param>
    public static void DisplayKeySetInfo(KeySet keySet, string title = "PGP Key Information")
    {
        var table = new Table()
            .Title(title)
            .BorderColor(Color.Grey)
            .AddColumn(new TableColumn("Property").Centered())
            .AddColumn(new TableColumn("Value").LeftAligned());

        // Primary key information
        var keyIdHex = Convert.ToHexString(keySet.KeyId);
        var fingerprintHex = Convert.ToHexString(keySet.Fingerprint);
        
        table.AddRow("Primary Key ID", $"[cyan]{keyIdHex}[/]");
        table.AddRow("Fingerprint", $"[green]{fingerprintHex}[/]");
        table.AddRow("Algorithm", keySet.MasterKey.Algorithm.ToString());
        table.AddRow("Creation Date", keySet.CreationTime.ToString("yyyy-MM-dd HH:mm:ss UTC"));
        
        // User ID information
        table.AddRow("User ID", $"[yellow]{Markup.Escape(keySet.PrimaryUserId.Value)}[/]");

        // Subkeys information
        table.AddRow("", ""); // Separator
        table.AddRow("[bold]Subkeys[/]", "");
        
        foreach (var subkey in keySet.Subkeys)
        {
            var usage = GetKeyUsageString(subkey);
            var subkeyIdHex = Convert.ToHexString(subkey.KeyId);
            table.AddRow($"  {usage}", $"[cyan]{subkeyIdHex}[/]");
        }

        AnsiConsole.Write(table);
    }

    /// <summary>
    /// Displays mnemonic phrase information in a formatted table.
    /// </summary>
    /// <param name="phrase">The mnemonic phrase.</param>
    /// <param name="info">The mnemonic information.</param>
    /// <param name="title">Optional title for the table.</param>
    public static void DisplayMnemonicInfo(string phrase, Mnemonikey.MnemonicInfo info, string title = "Mnemonic Information")
    {
        var table = new Table()
            .Title(title)
            .BorderColor(Color.Grey)
            .AddColumn(new TableColumn("Property").Centered())
            .AddColumn(new TableColumn("Value").LeftAligned());

        table.AddRow("Word Count", info.WordCount.ToString());
        table.AddRow("Type", info.IsEncrypted ? "[yellow]Encrypted[/]" : "[green]Plaintext[/]");
        table.AddRow("Creation Date", info.CreationTime.ToString("yyyy-MM-dd HH:mm:ss UTC"));
        table.AddRow("Era", info.Era.ToString());
        
        if (!info.IsEncrypted)
        {
            table.AddRow("Seed (hex)", $"[grey]{info.SeedHex}[/]");
        }

        AnsiConsole.Write(table);
    }

    /// <summary>
    /// Displays a numbered list of mnemonic words.
    /// </summary>
    /// <param name="words">The mnemonic words.</param>
    /// <param name="title">Optional title for the display.</param>
    /// <param name="showNumbers">Whether to show word numbers.</param>
    public static void DisplayMnemonicWords(string[] words, string title = "Recovery Phrase", bool showNumbers = true)
    {
        ColorConsole.WriteRule(title);
        
        if (showNumbers)
        {
            var columns = Math.Min(3, words.Length); // Show up to 3 columns
            var rows = (words.Length + columns - 1) / columns;
            
            var table = new Table()
                .BorderColor(Color.Grey)
                .HideHeaders();
            
            for (int col = 0; col < columns; col++)
            {
                table.AddColumn(new TableColumn("").LeftAligned());
            }
            
            for (int row = 0; row < rows; row++)
            {
                var rowData = new string[columns];
                
                for (int col = 0; col < columns; col++)
                {
                    var index = row + col * rows;
                    if (index < words.Length)
                    {
                        rowData[col] = $"[grey]{index + 1,2}.[/] [green]{words[index]}[/]";
                    }
                    else
                    {
                        rowData[col] = "";
                    }
                }
                
                table.AddRow(rowData);
            }
            
            AnsiConsole.Write(table);
        }
        else
        {
            ColorConsole.WriteInfo(string.Join(" ", words));
        }
        
        ColorConsole.WriteLine();
    }

    /// <summary>
    /// Displays a warning box with important information.
    /// </summary>
    /// <param name="title">The title of the warning.</param>
    /// <param name="messages">The warning messages.</param>
    public static void DisplayWarningBox(string title, params string[] messages)
    {
        var panel = new Panel(string.Join("\n", messages))
            .Header(title)
            .BorderColor(Color.Yellow)
            .Padding(1, 0);
            
        AnsiConsole.Write(panel);
    }

    /// <summary>
    /// Displays an information box.
    /// </summary>
    /// <param name="title">The title of the information box.</param>
    /// <param name="messages">The information messages.</param>
    public static void DisplayInfoBox(string title, params string[] messages)
    {
        var panel = new Panel(string.Join("\n", messages))
            .Header(title)
            .BorderColor(Color.Blue)
            .Padding(1, 0);
            
        AnsiConsole.Write(panel);
    }

    /// <summary>
    /// Displays an error box.
    /// </summary>
    /// <param name="title">The title of the error box.</param>
    /// <param name="messages">The error messages.</param>
    public static void DisplayErrorBox(string title, params string[] messages)
    {
        var panel = new Panel(string.Join("\n", messages))
            .Header(title)
            .BorderColor(Color.Red)
            .Padding(1, 0);
            
        AnsiConsole.Write(panel);
    }

    /// <summary>
    /// Gets a human-readable string for key usage.
    /// </summary>
    /// <param name="key">The key.</param>
    /// <returns>Key usage string.</returns>
    private static string GetKeyUsageString(IPgpKey key)
    {
        var usages = new List<string>();
        
        if (key.Usage.HasFlag(KeyUsage.Sign))
            usages.Add("Sign");
        if (key.Usage.HasFlag(KeyUsage.EncryptCommunications) || key.Usage.HasFlag(KeyUsage.EncryptStorage))
            usages.Add("Encrypt");
        if (key.Usage.HasFlag(KeyUsage.Authenticate))
            usages.Add("Auth");
        if (key.Usage.HasFlag(KeyUsage.Certify))
            usages.Add("Certify");
        
        return usages.Any() ? string.Join(", ", usages) : "Unknown";
    }
}