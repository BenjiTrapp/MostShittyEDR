---
title: "Challenge 21: Dynamic API Resolution"
difficulty: medium
category: "API Hook Evasion"
target_rule: 7
---

## Objective

Execute a program that calls `NtAllocateVirtualMemory` without Rule 7 detecting the import.

## Scanner Behavior

Rule 7 reads the PE Import Address Table (IAT) of new processes and cross-references imported function names against the loaded EDR hook profile:

```nim
proc ruleHookedApiImports(info: ProcessInfo, profile: HookProfile): seq[Detection] =
  let imports = readPeImports(info.imagePath)
  for imp in imports:
    if normalized in profile.hookedApis:
      matchedApis.add(imp)
```

The scanner only sees **static imports** — functions listed in the PE header's import directory at compile time.

## Rules

- The EDR must be running with `--profile crowdstrike` (or any profile that hooks `NtAllocateVirtualMemory`)
- Your program must successfully call `NtAllocateVirtualMemory`
- Rule 7 must NOT trigger a `HOOKED_API_IMPORT` detection for that API

## Hints

<details class="hint-box">
<summary>Hint 1</summary>
The scanner reads the PE file on disk, not the process memory at runtime.
</details>

<details class="hint-box">
<summary>Hint 2</summary>
What if the function isn't in the import table but is resolved at runtime?
</details>

<details class="hint-box">
<summary>Hint 3</summary>
`GetProcAddress(GetModuleHandle("ntdll.dll"), "NtAllocateVirtualMemory")` resolves the function without a static import.
</details>
