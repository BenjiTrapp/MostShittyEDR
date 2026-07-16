---
title: "Challenge 24: ntdll.dll Unhooking"
difficulty: hard
category: "API Hook Evasion"
target_rule: 7
---

## Objective

Demonstrate that the MostShittyEDR has no runtime hook integrity verification. Load a fresh copy of ntdll.dll and overwrite the hooked `.text` section — the EDR won't notice.

## Scanner Behavior

Rule 7 checks the PE import table once at process creation time:

```nim
proc ruleHookedApiImports(info: ProcessInfo, profile: HookProfile): seq[Detection] =
  let imports = readPeImports(info.imagePath)
  # one-shot check, no continuous monitoring
```

There is **no runtime verification** that hooks are still in place. The EDR never:
- Re-reads ntdll.dll's `.text` section
- Monitors `NtProtectVirtualMemory` calls against ntdll pages
- Checks for `MapViewOfFile` of system DLLs
- Validates syscall stub integrity

## Rules

- The EDR must be running with a hook profile loaded
- Your program must demonstrate unhooking ntdll.dll by restoring its `.text` section from disk
- The unhooking itself must go undetected

## Hints

<details class="hint-box">
<summary>Hint 1</summary>
Map a fresh copy of `C:\Windows\System32\ntdll.dll` from disk using `CreateFileMapping` + `MapViewOfFile`.
</details>

<details class="hint-box">
<summary>Hint 2</summary>
Find the `.text` section in both the in-memory (hooked) and on-disk (clean) copies.
</details>

<details class="hint-box">
<summary>Hint 3</summary>
Use `VirtualProtect` to make the in-memory `.text` section writable, then `memcpy` the clean code over the hooks. Restore the original protection afterward.
</details>
