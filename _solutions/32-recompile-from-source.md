---
title: "Solution 32: Recompile from Source"
difficulty: easy
category: "Signature Bypass"
---

[Back to Challenge]({{ '/challenges/32-recompile-from-source/' | relative_url }})

## Overview

Recompiling malware from source produces a binary with identical functionality but a completely different SHA256 hash. Exact-match signature detection is powerless against this.

## Solution

```powershell
# Example: Recompile Mimikatz from source
git clone https://github.com/gentilkiwi/mimikatz.git
cd mimikatz
msbuild mimikatz.sln /p:Configuration=Release /p:Platform=x64

# The resulting mimikatz.exe has a different hash
certutil -hashfile x64\mimikatz.exe SHA256
# Output: different from any hash in signatures/malware_hashes.txt

# Run it — Rule 6 does not trigger
.\x64\mimikatz.exe
```

```powershell
# Even simpler: recompile with a different flag
cl /O2 /Fe:tool.exe source.c    # optimization level changes the hash
cl /Od /Fe:tool.exe source.c    # different hash, same functionality
```

## Why It Works

PE files contain compilation artifacts that change between builds:

| PE Field | Why It Changes |
|----------|---------------|
| TimeDateStamp | Embedded build timestamp |
| Checksum | Recalculated from the new binary |
| Debug directory | Build path, PDB GUID |
| Rich header | Compiler/linker version stamps |
| Section alignment | Padding differs by compiler version |
| ASLR base | Randomized preferred load address |

Even identical source compiled twice in a row produces different hashes because the timestamp changes.

## Real-World Lesson

This is why hash-based detection alone is insufficient:

- **Signature databases** only catch known, exact builds of malware
- **Polymorphic malware** changes its hash automatically on each infection
- **Source-available tools** (Mimikatz, Rubeus, Sliver) can be recompiled trivially

Real EDRs layer multiple detection strategies:

| Strategy | Survives Recompilation? |
|----------|----------------------|
| SHA256 hash | No |
| Import hash (imphash) | Partially — changes if imports change |
| YARA rules | Yes — matches code patterns |
| Behavioral analysis | Yes — detects what the code does |
| ML classifiers | Usually — trained on structural features |
