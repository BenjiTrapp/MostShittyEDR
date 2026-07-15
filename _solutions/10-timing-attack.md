---
title: "Solution 10: Timing Attack"
difficulty: medium
category: "Process Monitoring Bypass"
---

[Back to Challenge]({{ '/challenges/10-timing-attack/' | relative_url }})

## Overview

The EDR polls processes at a fixed interval (default 500ms). A process that starts and exits within one interval is never captured in a snapshot.

## Solution

```powershell
# Most simple commands complete in < 10ms
# Run via cmd /c to ensure quick exit:
cmd.exe /c whoami > output.txt
cmd.exe /c net user > output.txt
cmd.exe /c ipconfig /all > output.txt

# The output is captured to a file even though
# the process is gone before the EDR polls
```

## Why It Works

`CreateToolhelp32Snapshot` captures a point-in-time view of all processes. Between snapshots (500ms gap), processes can spawn, execute, and exit without ever being visible.

```
Timeline:
  EDR Poll #1  -----[500ms gap]-----  EDR Poll #2
                  ^cmd starts  ^cmd exits
                  (never seen by either poll)
```

## Mitigation

Real EDR products use kernel callbacks (`PsSetCreateProcessNotifyRoutineEx`) which are called synchronously when a process is created - there is no polling gap. The kernel driver in `src/driver/driver.cpp` implements this approach.

## Increasing the Interval

```powershell
# Make it easier with a longer interval:
.\edr_agent.exe --interval 2000  # 2 second gaps
```
