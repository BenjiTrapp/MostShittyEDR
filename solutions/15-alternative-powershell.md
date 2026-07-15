---
title: "Solution 15: Alternative PowerShell Host"
difficulty: medium
category: "Execution Evasion"
---

[Back to Challenge]({{ '/challenges/15-alternative-powershell/' | relative_url }})

## Overview

Rule 5 only checks processes named `powershell.exe`. Any other process that can execute PowerShell bypasses this rule.

## Solution

```powershell
# Method 1: Use PowerShell 7 (pwsh.exe)
pwsh.exe -Command "Invoke-Expression 'whoami'"
pwsh.exe -EncodedCommand $encoded

# Method 2: Use cmd.exe to launch PowerShell indirectly
cmd.exe /c powershell -Command "IEX('whoami')"
# Note: cmd.exe is the process seen, not powershell.exe

# Method 3: Use System.Management.Automation from C#/dotnet
dotnet script -c "using System.Management.Automation; ..."

# Method 4: Use wmic
wmic process call create "powershell -enc ..."
# wmic.exe is the process, not powershell.exe
```

## Why It Works

```nim
if "powershell.exe" notin info.exeName.toLowerAscii():
  return  # Skips Rule 5 entirely for non-powershell processes
```

The check is on the process name, not on what the process actually does. `pwsh.exe`, `cmd.exe`, `wmic.exe`, and custom .NET hosts all execute PowerShell but are not named `powershell.exe`.
