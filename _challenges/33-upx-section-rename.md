---
title: "Challenge 33: UPX Section Name Rename"
difficulty: medium
category: "Packer & PE Evasion"
target_rule: 9
---

## Objective

Pack a binary with UPX (evading Rule 6's hash check), then rename the UPX section names to bypass Rule 9's packer detection.

## Prerequisites

```powershell
edr_agent.exe --signatures signatures/malware_hashes.txt --verbose --no-kill
```

## Scanner Behavior

Rule 9 checks section names against a hardcoded list of known packer signatures:

```nim
const PackerSectionNames = [
  "UPX0", "UPX1", "UPX2", "UPX!",
  ".aspack", ".adata", ...
]
```

Standard UPX creates sections named `UPX0`, `UPX1`, `UPX!` — an instant match.

## Rules

- Pack a binary with UPX so Rule 6 (hash check) no longer triggers
- Observe Rule 9 detecting the UPX section names
- Rename the UPX sections to something normal (e.g., `.text`, `.rdata`)
- Confirm that both Rule 6 and Rule 9 are now bypassed

## Hints

<details class="hint-box"><summary>Hint 1</summary>
UPX stores its section names in the PE section header table at fixed offsets. Each name is 8 bytes in the section header.
</details>

<details class="hint-box"><summary>Hint 2</summary>
Use a hex editor to find <code>UPX0</code> / <code>UPX1</code> in the section header table and replace with <code>.text</code> / <code>.rsrc</code>.
</details>

<details class="hint-box"><summary>Hint 3</summary>
<code>upx --force-overwrite -o packed.exe original.exe</code> to pack. Then a hex editor or Python script to rename sections. The EDR only checks names, not entropy or structure.
</details>
