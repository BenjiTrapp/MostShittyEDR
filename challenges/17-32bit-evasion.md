---
title: "Challenge 17: 32-Bit Process Evasion"
difficulty: medium
category: "Execution Evasion"
target_rule: "Architecture"
---

## Objective

Execute a 32-bit process to prevent the EDR from correctly reading its command line.

## Scanner Behavior

The EDR reads command lines using hardcoded 64-bit PEB offsets:

```nim
# ProcessParameters at PEB + 0x20 (64-bit)
ReadProcessMemory(hProc,
    cast[LPCVOID](pebAddr + 0x20'u64), ...)

# CommandLine at ProcessParameters + 0x70 (64-bit)
ReadProcessMemory(hProc,
    cast[LPCVOID](procParams + 0x70'u64), ...)
```

For 32-bit (WoW64) processes, the PEB has **different offsets**:
- ProcessParameters is at PEB + 0x10 (not 0x20)
- CommandLine is at ProcessParameters + 0x40 (not 0x70)

## Rules

- Compile or use a 32-bit executable
- Execute it with suspicious command-line arguments
- Show that the EDR reads garbage or empty command line data

## Hints

<details class="hint-box"><summary>Hint 1</summary>
The 32-bit PEB has a different layout than the 64-bit PEB. The EDR only knows 64-bit offsets.
</details>

<details class="hint-box"><summary>Hint 2</summary>
<code>C:\Windows\SysWOW64\cmd.exe</code> is a 32-bit version of cmd.exe.
</details>

<details class="hint-box"><summary>Hint 3</summary>
Reading at wrong offsets means the EDR gets garbage data (wrong memory addresses). The <code>ReadProcessMemory</code> call will either fail or return meaningless bytes.
</details>
