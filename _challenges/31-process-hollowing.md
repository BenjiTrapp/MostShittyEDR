---
title: "Challenge 31: Process Hollowing vs Hash Check"
difficulty: hard
category: "Signature Bypass"
target_rule: 6
---

## Objective

Bypass Rule 6 by loading malicious code into memory without changing the on-disk image that gets hashed.

## Prerequisites

Start the EDR with signatures loaded:

```powershell
edr_agent.exe --signatures signatures/malware_hashes.txt --verbose --no-kill
```

## Scanner Behavior

Rule 6 hashes the **on-disk file** pointed to by the process image path:

```nim
let imgHash = sha256File(info.imagePath)
```

It never inspects what's actually loaded in the process's memory. Process hollowing creates a suspended process (with a clean image), unmaps the original sections, and maps malicious code in its place.

## Rules

- Start a legitimate process (e.g., `svchost.exe`) in a suspended state
- Replace its memory with malicious code (process hollowing)
- Resume the thread — the EDR hashes the clean on-disk `svchost.exe`
- Rule 6 must not trigger

## Hints

<details class="hint-box"><summary>Hint 1</summary>
<code>CreateProcess</code> with <code>CREATE_SUSPENDED</code> flag, then <code>NtUnmapViewOfSection</code> + <code>VirtualAllocEx</code> + <code>WriteProcessMemory</code>.
</details>

<details class="hint-box"><summary>Hint 2</summary>
The EDR reads <code>info.imagePath</code> which still points to the original legitimate binary on disk. The hash matches a clean system binary, not your payload.
</details>

<details class="hint-box"><summary>Hint 3</summary>
This works because the EDR checks the file, not the memory. A real EDR with ETW-TI would see the <code>NtUnmapViewOfSection</code> and <code>NtWriteVirtualMemory</code> calls on a remote process.
</details>
