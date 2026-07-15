[![Nim](https://img.shields.io/badge/Nim-2.0+-FFE953?logo=nim&logoColor=white)](https://nim-lang.org)
[![Windows](https://img.shields.io/badge/Windows-Only-0078D6?logo=windows&logoColor=white)](https://www.microsoft.com/windows)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Educational](https://img.shields.io/badge/Purpose-Educational%20Only-red)](docs/EDR_BYPASS_TECHNIQUES.md)

<p align="center">
  <img src="static/logo.png" alt="MostShittyEDR Logo" width="400">
</p>
**The World's Most Intentionally Terrible Endpoint Detection & Response Agent**

> *"If you can't bypass this, you definitely need more practice"*

A deliberately weak EDR agent written in Nim, designed as a hands-on lab for learning EDR evasion techniques. Each detection rule contains intentional weaknesses that map to specific bypass challenges.

---

## Features

| Feature | Implementation | Intentional Weakness |
|---------|---------------|---------------------|
| Process Name Blacklist | Case-sensitive exact match | Renaming or case change bypasses |
| Command Line Keywords | Simple substring search | No deobfuscation, env vars bypass |
| Recon Detection | Detects recon commands | Result is `discard`ed - never blocks |
| LSASS Dump Detection | Tool name + keyword match | Requires both conditions - rename breaks it |
| PowerShell Analysis | Flag pattern matching | Only checks `powershell.exe`, not `pwsh.exe` |
| Hash-Based Detection | "Enterprise-grade" hash DB | Database is empty - pure security theater |
| Process Monitoring | Polling via Toolhelp32 | Timing gaps between polls |
| Command Line Reading | PEB reading (64-bit only) | Fails for elevated/protected/32-bit processes |

## Quick Start

### Prerequisites

- [Nim 2.0+](https://nim-lang.org/install.html)
- Windows 10/11 (64-bit)
- [winim](https://github.com/nickelc/winim) package (installed automatically)

### Build & Run

```powershell
# Install dependencies and build
make build

# Or manually:
nimble install winim -y
nim c -d:release --opt:size -o:edr_agent.exe src/edr_agent.nim

# Run the EDR agent
.\edr_agent.exe --verbose

# Run in detection-only mode (no process termination)
.\edr_agent.exe --verbose --no-kill

# Set custom polling interval (ms)
.\edr_agent.exe --interval 1000
```

### Lab Usage

1. **Terminal 1**: Start the EDR agent
   ```powershell
   .\edr_agent.exe --verbose --no-kill
   ```

2. **Terminal 2**: Try to execute commands without being detected
   ```powershell
   # This will be detected:
   whoami

   # Can you find a way that won't be detected?
   # See challenges/ for hints!
   ```

## Console Output

```
  __  __         _   ___ _    _ _   _          ___ ___  ___
 |  \/  |___ ___| |_/ __| |_ (_) |_| |_ _  _ | __|   \| _ \
 | |\/| / _ (_-<  _\__ \ ' \| |  _|  _| || | | _|| |) |   /
 |_|  |_\___/__/\__|___/_||_|_|\__|\__|\_, | |___|___/|_|_\
                                        |__/

  The World's Most Intentionally Terrible EDR
  "If you can't bypass this, you definitely need more practice"

  Detection Rules:
    [1] Process Name Blacklist    (12 entries)
    [2] Command Line Keywords     (12 patterns)
    [3] Recon Command Detection   (13 commands) [WARN ONLY]
    [4] LSASS Dump Detection      (8 indicators)
    [5] PowerShell Flag Analysis  (8 flags)
    [6] Hash-Based Detection      (0 hashes) [EMPTY]

[14:23:01.337] Initial snapshot: 142 processes
[14:23:01.337] Monitoring for new processes... (Ctrl+C to stop)
============================================================

[14:23:05.841] [CRITICAL] Blacklisted process detected: mimikatz.exe
               PID: 8472 | Image: mimikatz.exe
               [ACTION] Terminating PID 8472
               [+] Process terminated successfully
[14:23:12.105] [OK]       chrome.exe (PID: 9104)
```

## Challenges

20 bypass challenges across 5 categories, from Easy to Hard:

### Category 1: Process Name Evasion (Easy)

| # | Challenge | Difficulty | Target Rule |
|---|-----------|-----------|-------------|
| 1 | Binary Rename | Easy | Rule 1 |
| 2 | Case Sensitivity Exploit | Easy | Rule 1 |
| 3 | Copy and Rename | Easy | Rule 1 |
| 4 | Unlisted Tool | Easy | Rule 1 |

### Category 2: Command Line Obfuscation (Easy-Medium)

| # | Challenge | Difficulty | Target Rule |
|---|-----------|-----------|-------------|
| 5 | Path Manipulation | Easy | Rule 1 |
| 6 | Caret Insertion | Easy | Rule 2 |
| 7 | Environment Variable Substitution | Medium | Rule 2 |
| 8 | Base64 Encoded Commands | Medium | Rule 2, 5 |
| 9 | The Useless Rule | Easy | Rule 3 |

### Category 3: Process Monitoring Bypass (Medium)

| # | Challenge | Difficulty | Target Rule |
|---|-----------|-----------|-------------|
| 10 | Timing Attack | Medium | Architecture |
| 11 | Pre-Existing Process | Easy | Architecture |
| 12 | Living Off The Land | Medium | Rule 2, 3 |
| 13 | LSASS Without Keywords | Medium | Rule 4 |
| 14 | Tool Rename for LSASS | Medium | Rule 4 |

### Category 4: Execution Evasion (Medium-Hard)

| # | Challenge | Difficulty | Target Rule |
|---|-----------|-----------|-------------|
| 15 | Alternative PowerShell Host | Medium | Rule 5 |
| 16 | Elevated Process Evasion | Medium | Architecture |
| 17 | 32-Bit Process Evasion | Medium | Architecture |
| 18 | Unicode Process Names | Hard | Architecture |

### Category 5: Advanced Bypass (Hard)

| # | Challenge | Difficulty | Target Rule |
|---|-----------|-----------|-------------|
| 19 | Parent PID Spoofing | Hard | Architecture |
| 20 | The Empty Hash Database | Easy | Rule 6 |

> See [`challenges/`](challenges/) for full challenge descriptions with hints, and [`solutions/`](solutions/) for detailed walkthroughs.

## Architecture

```
MostShittyEDR/
├── src/
│   ├── edr_agent.nim          # User-mode EDR agent (Nim)
│   └── driver/
│       └── driver.cpp         # Kernel driver (C++, reference only)
├── challenges/                # 20 bypass challenges
├── solutions/                 # Detailed solution walkthroughs
├── docs/                      # Technical documentation
├── _config.yml                # GitHub Pages config
├── _layouts/                  # Jekyll layouts
├── assets/css/                # Site styles
├── Makefile                   # Build automation
└── MostShittyEDR.nimble       # Nim package config
```

### Detection Pipeline

```
New Process Detected (via Toolhelp32 polling)
    │
    ├─→ Rule 1: Process Name Blacklist  ──→ KILL (case-sensitive!)
    ├─→ Rule 2: Command Line Keywords   ──→ KILL (no deobfuscation!)
    ├─→ Rule 3: Recon Detection         ──→ discard (never blocks!)
    ├─→ Rule 4: LSASS Dump Detection    ──→ KILL (needs both conditions!)
    ├─→ Rule 5: PowerShell Analysis     ──→ ALERT (only powershell.exe!)
    └─→ Rule 6: Hash Check              ──→ discard (empty database!)
```

### Known Design Weaknesses (by Design)

1. **Polling-based monitoring** - Processes can execute between poll intervals
2. **Case-sensitive blacklist** - `Mimikatz.exe` != `mimikatz.exe`
3. **No command-line deobfuscation** - Carets, env vars, encoding all bypass
4. **Recon detection is theater** - Rule 3 detects but discards the result
5. **LSASS rule needs dual match** - Rename tool OR omit "lsass" keyword
6. **Only monitors powershell.exe** - `pwsh.exe`, `cmd.exe /c powershell` bypass
7. **Empty hash database** - Rule 6 has zero entries
8. **ASCII-only string handling** - Unicode characters become `?`
9. **64-bit PEB offsets only** - 32-bit processes have unreadable command lines
10. **No pre-existing process analysis** - Start before the EDR = invisible
11. **No DLL/module monitoring** - DLL injection is invisible
12. **No ETW integration** - No kernel-level telemetry

## Kernel Driver (Advanced Reference)

The `src/driver/driver.cpp` contains a Windows kernel driver that provides:
- Process creation/exit callbacks via `PsSetCreateProcessNotifyRoutineEx`
- Thread creation/exit callbacks via `PsSetCreateThreadNotifyRoutine`
- LSASS handle protection via `ObRegisterCallbacks`
- Kernel-level process blocking rules
- IOCTL communication with user-mode agents

> The kernel driver requires the Windows Driver Kit (WDK) and test-signing mode.
> It is included as educational reference material - the Nim agent works standalone.

## Educational Value

This project teaches:

- [x] How EDR agents monitor processes
- [x] Common detection rule patterns and their weaknesses
- [x] Process enumeration via Windows API
- [x] PEB reading for command line extraction
- [x] Why case-sensitive matching is a vulnerability
- [x] How `discard` patterns create detection gaps
- [x] Timing-based evasion of polling monitors
- [x] The gap between "detection" and "prevention"
- [x] Why hash-based detection alone is insufficient
- [x] Kernel vs. user-mode monitoring tradeoffs

## Legal Disclaimer

This software is provided for **educational and authorized security testing purposes only**.

- Use only in controlled lab environments or with explicit written authorization
- Never deploy against systems you do not own or have permission to test
- The authors are not responsible for misuse of this software
- This tool is intentionally weak and should never be used as actual endpoint protection

## License

MIT License - See [LICENSE](LICENSE) for details.

## Related Projects

- [MostShittyAV](https://github.com/BenjiTrapp/MostShittyAV) - The companion AMSI bypass lab
