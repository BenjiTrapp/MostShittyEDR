---
title: "Challenge 36: Runtime Unpacking Evasion"
difficulty: hard
category: "Packer & PE Evasion"
target_rule: 9
---

## Objective

Use a packer that unpacks the payload into a new memory allocation at runtime. The EDR only analyzes the initial PE on disk — it never re-scans process memory after execution starts.

## Prerequisites

```powershell
edr_agent.exe --signatures signatures/malware_hashes.txt --verbose --no-kill
```

## Scanner Behavior

Rule 9 runs **once** when a new process is detected. It reads the on-disk PE image:

```nim
let pe = analyzePeStructure(info.imagePath)
```

After the process starts running, the EDR never re-examines its memory. The unpacker stub (clean on disk) passes all checks, then decrypts and executes the real payload in memory.

## Rules

- Create a stub that loads encrypted payload from its `.data` section
- At runtime, allocate new memory, decrypt the payload, and jump to it
- The stub binary must have normal section names and no RWX sections on disk
- Rule 9 and Rule 6 must both not trigger

## Hints

<details class="hint-box"><summary>Hint 1</summary>
Use <code>VirtualAlloc</code> with <code>PAGE_READWRITE</code>, decrypt payload, then <code>VirtualProtect</code> to <code>PAGE_EXECUTE_READ</code>. The on-disk PE never has RWX.
</details>

<details class="hint-box"><summary>Hint 2</summary>
The key insight: the EDR checks files, not memory. After the process is running, it can <code>VirtualAlloc</code> new memory, write anything there, and execute it — the EDR will never know.
</details>

<details class="hint-box"><summary>Hint 3</summary>
This is how most modern malware works: a clean-looking loader/dropper passes static analysis, then unpacks/decrypts the real payload in memory at runtime. The EDR would need ETW-TI or memory scanning to catch this.
</details>
