---
title: "Challenge 01: Binary Rename"
difficulty: easy
category: "Process Name Evasion"
target_rule: 1
---

## Objective

Execute `mimikatz.exe` without the EDR detecting it via the process name blacklist.

## Scanner Behavior

Rule 1 checks new processes against a hardcoded list of known tool names:

```nim
const BlacklistedProcesses = [
  "mimikatz.exe", "procdump.exe", "procdump64.exe",
  "dumpert.exe", "nanodump.exe", "rubeus.exe", ...
]

proc ruleProcessBlacklist(info: ProcessInfo): seq[Detection] =
  for name in BlacklistedNames:
    if info.exeName == name:  # exact match
      ...
```

The check uses **exact string comparison** against the process executable name.

## Rules

- You must execute the actual mimikatz binary (or a test binary named `mimikatz.exe`)
- The EDR must not trigger a `BLACKLISTED_PROCESS` detection
- You may modify the filename but not the file content

## Hints

<details class="hint-box"><summary>Hint 1</summary>
The blacklist checks the exact filename. What happens if the filename changes?
</details>

<details class="hint-box"><summary>Hint 2</summary>
Windows doesn't care what you name an executable. Try renaming it.
</details>

<details class="hint-box"><summary>Hint 3</summary>
<code>copy mimikatz.exe m.exe</code> - does the EDR still detect <code>m.exe</code>?
</details>
