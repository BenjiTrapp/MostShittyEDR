---
title: "Challenge 34: Custom Packer / Crypter"
difficulty: hard
category: "Packer & PE Evasion"
target_rule: 9
---

## Objective

Use a custom packer or crypter with normal section names and no known signatures to completely evade both Rule 6 (hash check) and Rule 9 (packer detection).

## Prerequisites

```powershell
edr_agent.exe --signatures signatures/malware_hashes.txt --verbose --no-kill
```

## Scanner Behavior

Rule 9 relies on two weak indicators:

1. **Section name matching**: Only checks a hardcoded list of known packer names
2. **RWX section detection**: Checks for sections with `IMAGE_SCN_MEM_READ | WRITE | EXECUTE`

There is **no entropy analysis** — a section full of encrypted data with a normal name like `.text` is invisible to the scanner.

## Rules

- Write or use a custom packer that does not use known section names
- Avoid creating sections with RWX permissions (use `VirtualProtect` at runtime instead)
- The packed binary must successfully unpack and execute its payload
- Both Rule 6 and Rule 9 must not trigger

## Hints

<details class="hint-box"><summary>Hint 1</summary>
A minimal packer: XOR-encrypt the payload, store it in a <code>.data</code> section, add a stub in <code>.text</code> that decrypts and jumps to it.
</details>

<details class="hint-box"><summary>Hint 2</summary>
Use <code>RW</code> for the encrypted data section, then <code>VirtualProtect</code> to add execute permission at runtime. The static analysis never sees RWX.
</details>

<details class="hint-box"><summary>Hint 3</summary>
The EDR has no entropy analysis. A <code>.text</code> section with Shannon entropy of 7.99 (near-random encrypted data) looks identical to a normal <code>.text</code> section to this scanner.
</details>
