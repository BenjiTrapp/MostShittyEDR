---
title: "Challenge 23: Direct Syscalls"
difficulty: hard
category: "API Hook Evasion"
target_rule: 7
---

## Objective

Execute `NtAllocateVirtualMemory` without calling the ntdll.dll function at all — use a direct syscall to bypass both the import check AND any hypothetical userland hook.

## Scanner Behavior

Rule 7 operates entirely in user-mode and only checks static imports:

```nim
# WEAKNESS: No direct/indirect syscall detection
proc ruleHookedApiImports(info: ProcessInfo, profile: HookProfile): seq[Detection] =
  let imports = readPeImports(info.imagePath)
```

The scanner has **zero visibility** into direct syscalls because:
- Direct syscalls skip ntdll.dll entirely
- There is no kernel-level ETW-TI integration
- No minifilter or callback monitors the actual system call

## Rules

- The EDR must be running with a hook profile loaded
- Your program must use a **direct syscall** (not an ntdll.dll call)
- The syscall must successfully execute (e.g., allocate memory)

## Hints

<details class="hint-box">
<summary>Hint 1</summary>
In Windows, ntdll.dll is just a thin wrapper that puts a syscall number in EAX and executes the `syscall` instruction. You can do this yourself.
</details>

<details class="hint-box">
<summary>Hint 2</summary>
Research "Hell's Gate" — a technique that reads the syscall number from ntdll.dll on disk and then issues the syscall directly via inline assembly.
</details>

<details class="hint-box">
<summary>Hint 3</summary>
The syscall ID for `NtAllocateVirtualMemory` varies by Windows version. Hell's Gate resolves it dynamically by parsing ntdll.dll's export table and reading the `mov eax, <id>` instruction.
</details>
