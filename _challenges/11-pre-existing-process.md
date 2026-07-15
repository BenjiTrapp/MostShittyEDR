---
title: "Challenge 11: Pre-Existing Process"
difficulty: easy
category: "Process Monitoring Bypass"
target_rule: "Architecture"
---

## Objective

Have a "malicious" process running that the EDR never detects because it was started before the EDR.

## Scanner Behavior

On startup, the EDR takes an initial snapshot and marks all existing processes as "known":

```nim
let initial = enumerateProcesses()
gKnownPids = initHashSet[DWORD]()
for p in initial:
  gKnownPids.incl(p.pid)
```

Processes in the initial snapshot are **never analyzed**. The EDR only monitors for NEW processes.

## Rules

- Start a blacklisted tool or suspicious process BEFORE the EDR starts
- The process must still be running when the EDR starts
- Verify that the EDR does not detect or report it

## Hints

<details class="hint-box"><summary>Hint 1</summary>
The EDR only monitors new processes. Everything running at startup is assumed to be safe.
</details>

<details class="hint-box"><summary>Hint 2</summary>
Start <code>notepad.exe</code> (which is blacklisted), then start the EDR agent. Is notepad detected?
</details>

<details class="hint-box"><summary>Hint 3</summary>
This is a fundamental weakness of user-mode EDR agents that don't enumerate and scan existing processes on startup.
</details>
