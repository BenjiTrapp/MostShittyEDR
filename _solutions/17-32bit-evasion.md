---
title: "Solution 17: 32-Bit Process Evasion"
difficulty: medium
category: "Execution Evasion"
---

[Back to Challenge]({{ '/challenges/17-32bit-evasion/' | relative_url }})

## Overview

The EDR uses hardcoded 64-bit PEB offsets to read command lines. For 32-bit (WoW64) processes, these offsets are wrong, resulting in failed reads.

## Solution

```powershell
# Use the 32-bit cmd.exe
C:\Windows\SysWOW64\cmd.exe /c whoami

# Use a 32-bit version of a tool
# Compile as 32-bit or use existing x86 binaries

# The EDR tries to read PEB at wrong offsets:
# 64-bit: ProcessParameters at PEB + 0x20
# 32-bit: ProcessParameters at PEB + 0x10
# Result: ReadProcessMemory reads garbage -> empty command line
```

## Why It Works

The PEB structure differs between 32-bit and 64-bit processes:

| Field | 64-bit Offset | 32-bit Offset |
|-------|--------------|--------------|
| ProcessParameters | 0x20 | 0x10 |
| CommandLine | 0x70 | 0x40 |

The EDR always uses 64-bit offsets. For a 32-bit process, reading at offset 0x20 retrieves incorrect data (likely a different field), and `ReadProcessMemory` either fails or returns garbage that doesn't decode as a valid command line.

## Mitigation

A robust implementation would detect WoW64 processes using `IsWow64Process` and switch to the correct PEB offsets, or use `NtWow64QueryInformationProcess64` for cross-architecture reads.
