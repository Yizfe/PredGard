# Cheat Detection and Prevention for Predecessor 

This project is a C# application designed to monitor and detect suspicious modules loaded into the game process for Predecessor, focusing on identifying potential cheat injections that bypass Easy Anti-Cheat. The application specifically detects modified `twain_64.dll` files that attempt to masquerade as `kernel32.dll`, a tactic often used by cheat developers to avoid detection.

### Features
- **Real-Time Monitoring:** Continuously monitors the game process for module load events.
- **Hash Verification:** Computes the SHA-256 hash of each loaded module to compare it against a known hash for `kernel32.dll`. This helps identify if a cheat is spoofing `twain_64.dll` as `kernel32.dll`.
- **Size Verification:** Checks the file size of suspicious DLLs to further verify their authenticity.
- **Automatic Process Termination:** Terminates the game process if a suspicious module is detected, preventing the cheat from executing.
- **Error Handling and Retry Mechanism:** Implements retries for hash computation and file operations to handle potential file access issues caused by rapid cheat DLL deletion or manipulation.

### Example of Cheat Detection
The image below shows a suspicious `twain_64.dll` module detected in the game process, with properties altered to appear like `kernel32.dll`. This tool would detect such discrepancies based on the module’s hash and file size:

![Suspicious Module Detection](https://cdn.discordapp.com/attachments/1120891011581874237/1305179346528370778/wmokFRq.png?ex=6732167d&is=6730c4fd&hm=9aa4acb997a0a37e5c5cf25664e43b1ad526ae0bc51958efe642a8d62c11b477&)

### Demonstration
To illustrate the effectiveness of this code, I plan to create a demonstration video showing:
- **Without the Code Running**: The game is vulnerable to cheat injection, with `twain_64.dll` successfully loading without being detected.
- **With the Code Running**: The code detects and terminates the game process when `twain_64.dll` attempts to load, preventing the cheat from operating.

Once the video is available, it will be linked here: [Demonstration Video](https://cdn.discordapp.com/attachments/1043009166840700979/1281362094180274197/lv_0_20240905140941.mp4?ex=673273f1&is=67312271&hm=e35fb9a58bb7bee8edfc02e72a1f1aec4c8905c9631a045f5432c8b4acda18a0&)

In addition, I wrote this C# code to patch the vulnerability and prevent cheat injection, although I haven't had time to make the video yet. This demonstration will provide a clear comparison of the game's behavior with and without the code, showcasing its effectiveness in real-time.

### How It Works
1. **Process Identification**: The application identifies and continuously monitors the specified game process (`PredecessorClient-Win64-Shipping.exe`).
2. **ETW Monitoring**: Utilizes Event Tracing for Windows (ETW) to track module load events in real-time.
3. **Module Validation**: Each loaded module’s path and hash are checked against known values for legitimate system modules.
4. **Suspicious Module Detection**: If a suspicious hash (`610eb92c4053347a364e49793674ff46cc4824c5be5625a84c44cd4f6168c228`) is detected, the application will output a warning, log the event, and terminate the game process to prevent cheat execution. This hash is verified and legitimate for `kernel32.dll`. We can use this to detect a fake DLL module loaded into the game, as any module with this hash but named `twain_64.dll` would be flagged as suspicious.
5. **Optional Module Copying**: The program includes functionality to attempt copying the detected DLL for further analysis, though this may be unreliable due to the cheat’s anti-detection tactics.

### Code Overview
- **Main Monitoring Loop**: Continuously checks if the game is running, monitoring for module load events.
- **Hash and Size Verification**: The application verifies each DLL’s integrity by computing its hash and size, flagging any discrepancies.
- **Process Termination**: Stops the game process upon detection of a suspicious module, preventing potential cheat functionality.
  
### Usage Instructions
1. Clone this repository.
2. Ensure the `gameProcessName` variable in the code matches the executable name of the game you want to monitor.
3. Compile and run the application.
4. The console will display loaded modules in green, suspicious detections in red, and terminated processes in blue.

### Notes
- This tool is intended for educational and research purposes to understand and counteract game cheat injections.
- The `suspiciousHash` used in this application is specific to `kernel32.dll` but can be adjusted if other known module hashes are used by cheaters.
- Rapidly changing the contents of `twain_64.dll` or other DLLs might require frequent updates to the detection logic.
