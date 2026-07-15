---
title: "Solution 11: Pre-Existing Process"
difficulty: easy
category: "Process Monitoring Bypass"
---

[Back to Challenge]({{ '/challenges/11-pre-existing-process/' | relative_url }})

## Overview

The EDR takes an initial snapshot and marks all existing processes as "known". These are never analyzed.

## Solution

```powershell
# Step 1: Start the "malicious" process BEFORE the EDR
Start-Process notepad.exe  # notepad.exe is blacklisted

# Step 2: Start the EDR agent
.\edr_agent.exe --verbose

# Result: notepad.exe is in the initial snapshot
# and is marked as "known" - never analyzed
```

## Why It Works

```nim
let initial = enumerateProcesses()
gKnownPids = initHashSet[DWORD]()
for p in initial:
  gKnownPids.incl(p.pid)  # all existing PIDs marked as known
```

The EDR assumes everything running at startup is legitimate. It only watches for NEW process creation.

## Real-World Relevance

Real EDR products scan existing processes on startup, check loaded modules, and maintain persistent process trees. A rootkit or implant that starts before the EDR (e.g., via a boot-time driver or early service) could use this technique against weaker products.
