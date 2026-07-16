---
title: "Challenge 32: Recompile from Source"
difficulty: easy
category: "Signature Bypass"
target_rule: 6
---

## Objective

Evade Rule 6 by recompiling malware from source — the resulting binary has a different hash even though the functionality is identical.

## Prerequisites

Start the EDR with signatures loaded:

```powershell
edr_agent.exe --signatures signatures/malware_hashes.txt --verbose --no-kill
```

## Scanner Behavior

Rule 6 uses exact SHA256 matching. Two compilations of the same source code produce different hashes due to timestamps, compiler versions, optimization flags, and build paths embedded in the PE headers.

## Rules

- Take any known malware source (e.g., Mimikatz, Rubeus)
- Recompile it from source with any compiler
- Run the recompiled binary — Rule 6 must not trigger
- The functionality should be identical to the original

## Hints

<details class="hint-box"><summary>Hint 1</summary>
PE files contain timestamps, build paths, and compiler-specific metadata. Recompiling produces a binary with identical behavior but a completely different SHA256 hash.
</details>

<details class="hint-box"><summary>Hint 2</summary>
Even compiling the same source twice on the same machine may produce different hashes (timestamps change, ASLR base addresses differ).
</details>

<details class="hint-box"><summary>Hint 3</summary>
This is why signature-only detection is insufficient. Real EDRs combine hash checks with behavioral analysis, YARA rules, and import/section hashing to detect recompiled variants.
</details>
