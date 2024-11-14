/***************************************************************************
 * 
 * COPYRIGHT NOTICE
 * 
 * Title       : Game Injection Detection System
 * Description : This code is designed to monitor and detect internal and external
 *               DLL injections within a game process, identifying suspicious
 *               modules and preventing unauthorized manipulation through real-time
 *               process termination.
 * 
 * Creator     : @yizfe
 * Created On  : [March 10, 2024]
 * 
 * COPYRIGHT (c) [2024] @yizfe. All rights reserved.
 * 
 * LICENSE FOR USE
 * 
 * Permission is granted to game developers and studios to use, modify, and
 * integrate this code into their projects solely for the purpose of improving
 * game security and cheat detection. This code may be used to enhance and protect
 * their software, with credit to @yizfe as the original creator.
 * 
 * Redistribution or sale of this code as a standalone tool or as part of another
 * software library is prohibited. Distribution of this code or any derivative
 * works outside of game security purposes is allowed only with explicit written
 * consent from the creator.
 * 
 * DISCLAIMER
 * 
 * This software is provided "AS IS" without any warranty, express or implied,
 * including but not limited to the implied warranties of merchantability and
 * fitness for a particular purpose. The creator shall not be held liable for any
 * damage resulting from the use of this code.
 * 
 ***************************************************************************/


using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;
using System.Threading;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;

class Program
{
    private static HashSet<string> copiedModules = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    private static List<string> loadedModules = new List<string>();
    private static List<Process> loadedExternal = new List<Process>();
    private static int gameProcessId = -1; // Store the game process ID
    private static bool monitorTaskRunning = false; // Track if the monitoring task is already running

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

                    // Start MonitorSvchostWithConhost in a separate task only if it's not already running
                    if (!monitorTaskRunning)
                    {
                        monitorTaskRunning = true;
                        Task.Run(() =>
                        {
                            MonitorSvchostWithConhost();
                            monitorTaskRunning = false; // Reset when task completes
                        });
                    }
                }
                else
                {
                    Thread.Sleep(1000);
                    continue;
                }
            }


            /// <summary>
            /// Start Monitoring Internal Game Injection - Optimized for detecting spoofed or fake DLL injections in the running game process.
            ///
            /// This section monitors real-time module load events specifically for the active game process, filtering modules by the game’s process ID.
            /// It checks each loaded module's hash against known suspicious hashes to detect any internal injections or spoofed DLLs that attempt 
            /// to mimic legitimate modules. The process is kept highly optimized to prevent any delays, as cheats may quickly delete these fake DLLs
            /// after loading. 
            ///
            /// Important: Do not add or delete code lines within this block. Each line here is critical to performance, and additional processing 
            /// could result in missed detections due to the high-speed deletion of spoofed DLLs. 
            /// </summary>

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

                        // Attempt to compute the hash with a retry mechanism  this for internal cheats
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




    /// <summary>
    /// MonitorSvchostWithConhost - Monitors svchost.exe processes and their conhost.exe child processes to detect external cheat injections.
    /// 
    /// This method continuously scans all svchost.exe instances on the system, identifying any conhost.exe processes spawned as their child.
    /// If a conhost.exe process is detected as a child of svchost.exe, it then checks the modules loaded in that conhost.exe instance for
    /// suspicious modules that are often associated with external cheat injections. If any such modules are found, it logs the detection,
    /// attempts to terminate both the conhost.exe and svchost.exe processes, and, as a safeguard, also terminates the main game process to
    /// prevent the cheat from continuing. 
    /// 
    /// The method runs on a separate thread with a 5000ms delay between checks to minimize CPU usage.
    /// </summary>

    static void MonitorSvchostWithConhost()
    {
        string hackProcessName = "svchost";
        string targetChildProcessName = "conhost";

        while (true)
        {
            // Find all svchost.exe processes
            Process[] svchostProcesses = Process.GetProcessesByName(hackProcessName);

            if (svchostProcesses.Length > 0)
            {
                foreach (var process in svchostProcesses)
                {
                    // Check each child process of svchost.exe to see if it's conhost.exe
                    foreach (Process childProcess in Process.GetProcessesByName(targetChildProcessName))
                    {
                        // Verify if conhost.exe is a child of svchost.exe
                        if (GetParentProcessId(childProcess.Id) == process.Id)
                        {
                            ExternalCheatChildProcess(childProcess); // Log the child process detection

                            // Monitor for suspicious modules loaded in conhost.exe
                            var childModules = childProcess.Modules;
                            bool suspiciousModuleFound = false;

                            foreach (ProcessModule module in childModules)
                            {
                                if (module.ModuleName.Equals("kernel32.dll", StringComparison.OrdinalIgnoreCase) ||
                                    module.ModuleName.Equals("ntdll.dll", StringComparison.OrdinalIgnoreCase) ||
                                    module.ModuleName.Equals("user32.dll", StringComparison.OrdinalIgnoreCase) ||
                                    module.ModuleName.Equals("kernelbase.dll", StringComparison.OrdinalIgnoreCase) ||
                                    module.ModuleName.Equals("advapi32.dll", StringComparison.OrdinalIgnoreCase) ||
                                    module.ModuleName.Equals("gdi32.dll", StringComparison.OrdinalIgnoreCase) ||
                                    module.ModuleName.Equals("dinput8.dll", StringComparison.OrdinalIgnoreCase) ||
                                    module.ModuleName.Equals("d3d9.dll", StringComparison.OrdinalIgnoreCase))
                                {
                                    suspiciousModuleFound = true;
                                    break;
                                }
                            }

                            if (suspiciousModuleFound)
                            {
                                Console.ForegroundColor = ConsoleColor.Yellow;
                                Console.WriteLine($"Potential external injection detected: svchost.exe spawning conhost.exe (PID: {childProcess.Id}) with suspicious modules loaded.");
                                Console.ResetColor();

                                // Attempt to stop the detected process and the game process as a fallback
                                StopProcess(childProcess.Id); // Attempt to stop conhost.exe
                                StopProcess(process.Id);      // Attempt to stop svchost.exe
                                StopProcess(gameProcessId);    // Stop the game process as a fallback

                                Environment.Exit(0);
                            }
                        }
                    }
                }
            }

            Thread.Sleep(5000); // Delay between checks to reduce CPU usage
        }
    }

    // Use native Windows API calls to get the parent process ID
    [DllImport("kernel32.dll")]
    private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll")]
    private static extern bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

    [DllImport("kernel32.dll")]
    private static extern bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESSENTRY32
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExeFile;
    }

    private static int GetParentProcessId(int processId)
    {
        IntPtr handle = CreateToolhelp32Snapshot(2, 0);
        if (handle == IntPtr.Zero) return 0;

        PROCESSENTRY32 pe32 = new PROCESSENTRY32 { dwSize = (uint)Marshal.SizeOf(typeof(PROCESSENTRY32)) };

        if (Process32First(handle, ref pe32))
        {
            do
            {
                if (pe32.th32ProcessID == processId)
                {
                    return (int)pe32.th32ParentProcessID;
                }
            } while (Process32Next(handle, ref pe32));
        }

        return 0;
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

    static void ExternalCheatChildProcess(Process childProcess)
    {
        if (!loadedExternal.Contains(childProcess))
        {
            loadedExternal.Add(childProcess);
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine($"svchost.exe detected a child process: {childProcess.ProcessName} (PID: {childProcess.Id})");
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
                Thread.Sleep(50);
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
