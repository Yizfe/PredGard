using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;
using System.Threading;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;

class Program
{
    private static HashSet<string> copiedModules = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    private static List<string> loadedModules = new List<string>();
    private static int gameProcessId = -1; // Store the game process ID

    // The specific hash to detect
    private const string suspiciousHash = "610eb92c4053347a364e49793674ff46cc4824c5be5625a84c44cd4f6168c228"; // <-- This hash is verified and legitimate for kernel32.dll. We can use this to detect a fake DLL module loaded into the game.

    static void Main()
    {
        string gameProcessName = "PredecessorClient-Win64-Shipping";
        Console.WriteLine($"Starting ETW monitoring for {gameProcessName} module load events...");

        // Loop to ensure continuous monitoring
        while (true)
        {
            if (gameProcessId == -1 || !IsGameRunning())
            {
                // Find the process ID of the game
                Process[] processes = Process.GetProcessesByName(gameProcessName);
                if (processes.Length > 0)
                {
                    gameProcessId = processes[0].Id;
                    Console.WriteLine($"{gameProcessName} detected (PID: {gameProcessId}). Monitoring modules...");
                }
                else
                {
                    Thread.Sleep(1000); // Wait before trying again
                    continue;
                }
            }

            // Start monitoring for module load events only if the game is running
            using (var session = new TraceEventSession("MyKernelAndClrEventsSession"))
            {
                session.EnableKernelProvider(KernelTraceEventParser.Keywords.ImageLoad);

                session.Source.Kernel.ImageLoad += delegate (ImageLoadTraceData data)
                {
                    // Filter events by the game process ID
                    if (data.ProcessID == gameProcessId)
                    {
                        string moduleName = data.FileName;

                        // Track every loaded module in the list
                        TrackLoadedModule(moduleName);

                        // Attempt to compute the hash with a retry mechanism
                        string moduleHash = TryComputeHashWithRetries(moduleName);
                        if (moduleHash == suspiciousHash && !copiedModules.Contains(moduleName))
                        {
                            long moduleSize = GetFileSize(moduleName);

                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine($"Suspicious module loaded: {moduleName} with hash: {moduleHash} and size: {moduleSize} bytes");
                            Console.ResetColor();

                            // Uncomment if you want to test it; please read comments in this function call.
                            // TryCopyDllWithRetry(moduleName);

                            // Attempt to stop the process that loaded the suspicious module
                            StopProcess(data.ProcessID);
                            Environment.Exit(0);
                        }
                    }
                };

                session.Source.Process(); // Start listening to events
            }

        }
    }

    static bool IsGameRunning()
    {
        try
        {
            Process.GetProcessById(gameProcessId);
            return true;
        }
        catch (ArgumentException)
        {
            // Process does not exist anymore
            gameProcessId = -1; // Reset the ID to search for the game again
            return false;
        }
    }

    static void TrackLoadedModule(string moduleName)
    {
        if (!loadedModules.Contains(moduleName))
        {
            loadedModules.Add(moduleName);
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"Module loaded: {moduleName}");
            Console.ResetColor();
        }
    }

    static string TryComputeHashWithRetries(string filePath)
    {
        int retries = 5;
        for (int attempt = 1; attempt <= retries; attempt++)
        {
            try
            {
                using (var sha256 = SHA256.Create())
                using (var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    byte[] hashBytes = sha256.ComputeHash(stream);
                    return BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
                }
            }
            catch (IOException ex)
            {
                Console.WriteLine($"Attempt {attempt} to compute hash failed: {ex.Message}");
                Thread.Sleep(50); // Short wait before retrying
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Unexpected error computing hash for {filePath}: {ex.Message}");
                break;
            }
        }
        Console.WriteLine($"Could not compute hash for {filePath} as it may have been deleted.");
        return "Hash unavailable";
    }

    static long GetFileSize(string filePath)
    {
        try
        {
            FileInfo fileInfo = new FileInfo(filePath);
            return fileInfo.Length;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error getting file size for {filePath}: {ex.Message}");
            return -1; // Indicate that file size couldn't be retrieved
        }
    }

    // I created this function to save the cheat DLL "twain_64.dll." However, it looks like the cheat might be manipulating the file at the path C:\Windows\System32\twain_64.dll to mimic the characteristics of kernel32.dll.
    // This could involve swapping file contents or using file redirection to avoid detection, ultimately resulting in saving the legitimate kernel32.dll instead of the actual cheat DLL.
    static void TryCopyDllWithRetry(string moduleName)
    {
        string destinationPath = Path.Combine(Environment.CurrentDirectory, "SavedDLLs", Path.GetFileName(moduleName));

        Directory.CreateDirectory(Path.GetDirectoryName(destinationPath));

        int retries = 3;
        bool success = false;

        for (int attempt = 1; attempt <= retries; attempt++)
        {
            try
            {
                File.Copy(moduleName, destinationPath, overwrite: true);
                copiedModules.Add(moduleName);
                Console.WriteLine($"Successfully copied {moduleName} to {destinationPath}");
                success = true;
                break;
            }
            catch (IOException ex)
            {
                if (attempt == retries)
                {
                    Console.WriteLine($"Failed to copy DLL after {retries} attempts: {ex.Message}");
                }
                else
                {
                    Thread.Sleep(50); // Short wait before retrying
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Unexpected error: {ex.Message}");
                break;
            }
        }

        if (!success)
        {
            Console.WriteLine($"Could not save {moduleName} as it was deleted too quickly.");
        }
    }

    static void StopProcess(int processId)
    {
        try
        {
            Process process = Process.GetProcessById(processId);
            Console.ForegroundColor = ConsoleColor.Blue;
            Console.WriteLine($"Terminating process: {process.ProcessName} (PID: {processId})");
            process.Kill();
            Console.WriteLine("Process terminated successfully.");
            Console.ResetColor();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to terminate process (PID: {processId}): {ex.Message}");
        }
    }
}
