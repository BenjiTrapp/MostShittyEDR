---
title: "Challenge 02: Case Sensitivity Exploit"
difficulty: easy
category: "Process Name Evasion"
target_rule: 1
---

## Objective

Run a blacklisted process by exploiting case-sensitive string comparison.

## Scanner Behavior

The blacklist comparison uses `==` which is **case-sensitive** in Nim:

```nim
if info.exeName == name:  # "Mimikatz.exe" != "mimikatz.exe"
```

The blacklist contains lowercase entries only: `"mimikatz.exe"`, `"procdump.exe"`, etc.

## Rules

- You must keep a recognizable variant of the original tool name
- The EDR must not trigger a `BLACKLISTED_PROCESS` detection
- Only the casing of the filename may change

## Hints

<details class="hint-box"><summary>Hint 1</summary>
The string comparison is case-sensitive. What's the casing of the blacklist entries?
</details>

<details class="hint-box"><summary>Hint 2</summary>
Windows filesystems are case-insensitive. <code>MIMIKATZ.EXE</code> and <code>mimikatz.exe</code> are the same file.
</details>

<details class="hint-box"><summary>Hint 3</summary>
Try: <code>rename mimikatz.exe Mimikatz.exe</code> and then run <code>Mimikatz.exe</code>
</details>
