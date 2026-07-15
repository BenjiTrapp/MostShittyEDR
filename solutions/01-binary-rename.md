---
title: "Solution 01: Binary Rename"
difficulty: easy
category: "Process Name Evasion"
---

[Back to Challenge]({{ '/challenges/01-binary-rename/' | relative_url }})

## Overview

The EDR checks process names against a hardcoded blacklist using exact string comparison. Simply renaming the executable defeats the check.

## Solution

```powershell
# Copy the tool to a new name
copy mimikatz.exe m.exe

# Run the renamed copy
.\m.exe

# Or use a more creative name
copy mimikatz.exe WindowsUpdate.exe
.\WindowsUpdate.exe
```

## Why It Works

The blacklist check is a simple equality comparison:

```nim
if info.exeName == name:  # only matches exact string
```

`m.exe` does not equal `mimikatz.exe`, so the rule never triggers. The EDR has **no hash-based detection** (Rule 6 database is empty), so it cannot identify binaries by their content.

## How to Verify

1. Start the EDR: `.\edr_agent.exe --verbose --no-kill`
2. Run `.\mimikatz.exe` - should trigger `BLACKLISTED_PROCESS`
3. Run `copy mimikatz.exe m.exe && .\m.exe` - should show `[OK]`

## Real-World Relevance

Real EDR products use hash databases, YARA rules, and behavioral analysis to identify binaries regardless of filename. This bypass only works against signature-based name checks.
