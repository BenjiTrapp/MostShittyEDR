---
title: "Challenge 22: DLL Proxy Call"
difficulty: medium
category: "API Hook Evasion"
target_rule: 7
---

## Objective

Execute hooked ntdll APIs by placing the call inside a loaded DLL rather than the main executable.

## Scanner Behavior

Rule 7 parses the PE imports of the **main executable only**:

```nim
proc ruleHookedApiImports(info: ProcessInfo, profile: HookProfile): seq[Detection] =
  let imports = readPeImports(info.imagePath)  # only the .exe!
```

It does not scan DLLs loaded by the process.

## Rules

- The EDR must be running with a hook profile loaded
- Your main .exe must NOT import any hooked APIs directly
- A DLL loaded by your .exe must call the hooked API successfully

## Hints

<details class="hint-box">
<summary>Hint 1</summary>
The scanner checks `info.imagePath` — the path to the .exe file. What about DLLs?
</details>

<details class="hint-box">
<summary>Hint 2</summary>
Create a DLL that imports `NtWriteVirtualMemory` and have your .exe load it with `LoadLibrary`.
</details>

<details class="hint-box">
<summary>Hint 3</summary>
The DLL's IAT is never scanned because `readPeImports` is only called on the main executable path.
</details>
