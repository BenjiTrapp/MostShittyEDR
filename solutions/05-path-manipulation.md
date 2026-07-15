---
title: "Solution 05: Path Manipulation"
difficulty: easy
category: "Command Line Obfuscation"
---

[Back to Challenge]({{ '/challenges/05-path-manipulation/' | relative_url }})

## Overview

`PROCESSENTRY32W.szExeFile` contains only the filename (not the full path), so Rule 1 always sees just the executable name regardless of how it was invoked.

## Solution

This challenge is actually a learning exercise: path manipulation does **not** bypass Rule 1 because `szExeFile` strips the path automatically.

However, the **command line** (used by Rule 2) preserves the full path as typed. This means you can use path tricks to hide keywords in the command line:

```powershell
# The command line contains the full path, not "whoami"
C:\Windows\System32\who""ami.exe

# Using environment variables in paths
%SystemRoot%\System32\whoami.exe
# The PEB stores %SystemRoot% unexpanded
```

## Key Insight

Rule 1 (process name) is path-independent. Rule 2 (command line) sees exactly what was typed, including path components and shell tricks.
