<div align="center">

<img src="static/logo.png" alt="MostShittyEDR Logo" width="500" />

</div>
<br><br>

# MostShittyEDR

### *The World's Most Intentionally Terrible Endpoint Detection & Response Agent*

[![Nim](https://img.shields.io/badge/Nim-2.0+-yellow.svg?style=flat-square&logo=nim)](https://nim-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows-0078D6.svg?style=flat-square&logo=windows)](https://www.microsoft.com/windows)
[![Status](https://img.shields.io/badge/status-Educational%20Only-red.svg?style=flat-square)](README.md)

**An educational EDR agent built in Nim to demonstrate process monitoring, detection techniques, and their bypasses.**

[Features](#-features) • [Quick Start](#quick-start) • [Challenges](#-the-challenge) • [Architecture](#-architecture) • [Detection Methods](#-detection-methods-explained) • [EDR Explained](https://benjitrapp.github.io/MostShittyEDR/edr-explained/) • [Resources](#-resources)

</div>

---

## Overview

**MostShittyEDR** is a deliberately weak EDR agent designed for **security research**, **education**, and **red team training**. It implements basic detection methods that mirror real-world EDR engines but with intentional weaknesses mapped to specific bypass challenges.

> *"If you can't bypass this, you definitely need more practice"*

> :warning: **Disclaimer**: This is NOT production security software. It's an educational tool for understanding EDR evasion techniques.

---

## Features

<table>
<tr>
<td width="50%">

### Detection Engines

- **Process Name Blacklist**
  - Case-sensitive exact match
  - 12 hardcoded tool names
  - No path or hash validation

- **Command Line Analysis**
  - Keyword substring search
  - No deobfuscation support
  - ASCII-only toLower

- **LSASS Dump Detection**
  - Tool name + keyword dual match
  - Easily broken by renaming

</td>
<td width="50%">

### Technical Features

- **Process Monitoring**
  - Toolhelp32 snapshot polling
  - PEB reading for command lines
  - 64-bit process support

- **Response Actions**
  - Process termination (configurable)
  - Detection-only mode (--no-kill)
  - Adjustable poll interval

- **Detailed Logging**
  - Timestamped output
  - Color-coded severity levels
  - Step-by-step detection trace

</td>
</tr>
</table>

---

## Quick Start

### Prerequisites

```bash
# Windows with Nim 2.0+
winget install nim-lang.Nim
```

### Build & Run

```powershell
# Install dependencies and build
make build

# Or manually:
nimble install winim -y
nim c -d:release --opt:size -o:edr_agent.exe src/edr_agent.nim

# Run the EDR agent (verbose mode)
.\edr_agent.exe --verbose

# Run in detection-only mode (no process termination)
.\edr_agent.exe --verbose --no-kill

# Set custom polling interval (ms)
.\edr_agent.exe --interval 1000
```

### Lab Usage

```powershell
# Terminal 1: Start the EDR agent
.\edr_agent.exe --verbose --no-kill

# Terminal 2: Try to execute commands without being detected
whoami          # This WILL be detected
# Can you find a way that won't be?
```

---

## The Challenge

> **Can you bypass the EDR?**
> This agent uses common detection patterns found in real-world EDR products.
> Your mission: Execute tools and commands without being detected or killed!

### Known Vulnerabilities

- :unlock: Case-sensitive blacklist (`Mimikatz.exe` != `mimikatz.exe`)
- :unlock: No command-line deobfuscation (carets, env vars, encoding all bypass)
- :unlock: Recon detection is theater (Rule 3 detects but discards the result)
- :unlock: LSASS rule needs dual match (rename tool OR omit "lsass" keyword)
- :unlock: Only monitors `powershell.exe` (not `pwsh.exe`)
- :unlock: Empty hash database (Rule 6 has zero entries)
- :unlock: Polling-based monitoring (timing gaps between scans)
- :unlock: No pre-existing process analysis (start before EDR = invisible)

**20 challenges across 5 categories, from Easy to Hard!**

---

## Example Output

```console
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

---

## Architecture

### Detection Pipeline

```
New Process Detected (via Toolhelp32 polling)
    |
    +-> Rule 1: Process Name Blacklist  --> KILL (case-sensitive!)
    +-> Rule 2: Command Line Keywords   --> KILL (no deobfuscation!)
    +-> Rule 3: Recon Detection         --> discard (never blocks!)
    +-> Rule 4: LSASS Dump Detection    --> KILL (needs both conditions!)
    +-> Rule 5: PowerShell Analysis     --> ALERT (only powershell.exe!)
    +-> Rule 6: Hash Check              --> discard (empty database!)
```

### Project Structure

```
MostShittyEDR/
├── src/
│   ├── edr_agent.nim              # User-mode EDR agent (Nim)
│   └── driver/
│       └── driver.cpp             # Kernel driver (C++, reference only)
├── _challenges/                   # 20 bypass challenges
├── _solutions/                    # Detailed solution walkthroughs
├── docs/                          # Technical documentation
├── static/                        # Logo and assets
├── _config.yml                    # GitHub Pages config
├── _layouts/                      # Jekyll layouts
├── assets/css/                    # Site styles
├── Makefile                       # Build automation
└── MostShittyEDR.nimble           # Nim package config
```

---

## Detection Methods Explained

### 1. Process Name Blacklist
```nim
const blacklist = [
  "mimikatz.exe", "rubeus.exe", "sharphound.exe",
  "procdump.exe", "psexec.exe", "cobaltstrike.exe", ...
]
```
Case-sensitive exact match against a static list. Rename = bypass.

### 2. Command Line Keywords
```nim
const keywords = [
  "sekurlsa", "kerberos::list", "invoke-mimikatz",
  "dump", "hashdump", "lsass", ...
]
```
Substring search with no deobfuscation. Carets, env vars, and encoding all bypass.

### 3. Recon Detection (Security Theater)
```nim
const reconCmds = ["whoami", "ipconfig", "netstat", "systeminfo", ...]
# Result is `discard`ed - detects but NEVER blocks
```
The detection fires but the result is thrown away. Pure theater.

### 4. LSASS Dump Detection
```nim
# Requires BOTH conditions:
# 1. Tool name matches (procdump, comsvcs, etc.)
# 2. Command line contains "lsass"
```
Rename the tool OR omit the keyword and the rule fails.

### 5. PowerShell Flag Analysis
```nim
# Only checks processes named "powershell.exe"
# pwsh.exe, cmd.exe /c powershell, and PowerShell ISE are invisible
```

### 6. Hash-Based Detection
```nim
const hashDB: seq[string] = @[]  # Empty!
```
Zero entries. Enterprise-grade security theater.

---

## Challenge Categories

| Category | Challenges | Difficulty | Target |
|----------|-----------|-----------|--------|
| **Process Name Evasion** | 01-04 | Easy | Rule 1 |
| **Command Line Obfuscation** | 05-09 | Easy-Medium | Rules 2, 3, 5 |
| **Process Monitoring Bypass** | 10-14 | Medium | Architecture, Rule 4 |
| **Execution Evasion** | 15-18 | Medium-Hard | Architecture, Rule 5 |
| **Advanced Bypass** | 19-20 | Easy-Hard | Architecture, Rule 6 |

See the [Challenge Browser](https://benjitrapp.github.io/MostShittyEDR/challenges/) for full descriptions with hints, and the [Solutions](https://benjitrapp.github.io/MostShittyEDR/solutions/) for detailed walkthroughs.

---

## Kernel Driver (Advanced Reference)

The `src/driver/driver.cpp` contains a Windows kernel driver providing:

- Process creation/exit callbacks via `PsSetCreateProcessNotifyRoutineEx`
- Thread creation/exit callbacks via `PsSetCreateThreadNotifyRoutine`
- LSASS handle protection via `ObRegisterCallbacks`
- Kernel-level process blocking rules
- IOCTL communication with user-mode agents

> The kernel driver requires the Windows Driver Kit (WDK) and test-signing mode. It is included as educational reference material.

---

## Educational Value

This project demonstrates:

- :white_check_mark: **EDR Architecture** - Agent pattern, polling, detection pipelines
- :white_check_mark: **Process Monitoring** - Toolhelp32 snapshots, PEB reading
- :white_check_mark: **Detection Rules** - Blacklists, keywords, heuristics, hashes
- :white_check_mark: **Rule Weaknesses** - Case sensitivity, missing deobfuscation, timing gaps
- :white_check_mark: **Evasion Techniques** - Renaming, encoding, timing, privilege escalation
- :white_check_mark: **Kernel vs User-Mode** - Why user-mode polling is fundamentally limited
- :white_check_mark: **Nim Programming** - Windows API, process manipulation, systems programming

---

## Resources

### EDR Internals
- [EDR Explained (MostShittyEDR)](https://benjitrapp.github.io/MostShittyEDR/edr-explained/) - How real EDRs work
- [Understanding and Attacking EDRs](https://benjitrapp.github.io/attacks/2024-08-21-edr-and-malware/) - Deep dive into hooking, syscalls, and kernel bypass
- [EDR Bypass Roadmap](https://benjitrapp.github.io/attacks/2026-01-18-EDR-bypass-roadmap/) - Strategic approach to bypassing EDR

### Companion Projects
- [MostShittyAV](https://github.com/BenjiTrapp/MostShittyAV) - The AMSI bypass companion lab

### Nim Language
- [Nim Official Website](https://nim-lang.org/)
- [Nim Documentation](https://nim-lang.org/documentation.html)
- [winim Package](https://github.com/nickelc/winim) - Windows API bindings for Nim

### Security Research
- [MITRE ATT&CK - Defense Evasion](https://attack.mitre.org/tactics/TA0005/)
- [LOLBAS Project](https://lolbas-project.github.io/) - Living Off The Land Binaries

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## :warning: Legal Notice

**This tool is for educational and research purposes only.**

- :x: Do not use on systems you don't own or have explicit permission to test
- :x: Do not use for malicious purposes
- :x: Not a replacement for real endpoint security
- :white_check_mark: Use in controlled lab environments only
- :white_check_mark: Understand applicable laws and regulations in your jurisdiction

**The author assumes no liability for misuse of this software.**

---

<div align="center">

### Happy Hunting!

*Made with Nim for the security research community*

**[:star: Star this repo](../../stargazers)** • **[:bug: Report Bug](../../issues)** • **[:bulb: Request Feature](../../issues)**

</div>
