---
title: "Challenge 35: PE Header Obfuscation (Astral-PE)"
difficulty: hard
category: "Packer & PE Evasion"
target_rule: 9
---

## Objective

Use PE header obfuscation (e.g., [Astral-PE](https://github.com/DosX-dev/Astral-PE)) to corrupt or manipulate PE headers so the EDR's parser fails silently and returns no analysis.

## Prerequisites

```powershell
edr_agent.exe --signatures signatures/malware_hashes.txt --verbose --no-kill
```

## Scanner Behavior

Rule 9 parses the PE header sequentially:

```nim
proc analyzePeStructure(imagePath: string): PeAnalysis =
  ...
  if dosHeader[0] != 0x4D or dosHeader[1] != 0x5A: return
  ...
  if peData[0] != ord('P') or peData[1] != ord('E'): return
  ...
```

If any parsing step fails, the function returns `PeAnalysis(valid: false)` and Rule 9 produces **zero detections**. The binary can still execute because the Windows PE loader is more tolerant than this parser.

## Rules

- Apply PE header obfuscation to a binary (e.g., using Astral-PE)
- The obfuscated binary must still execute correctly on Windows
- Rule 9's `analyzePeStructure` must fail to parse it (returns `valid: false`)
- No Rule 9 detections should trigger

## Hints

<details class="hint-box"><summary>Hint 1</summary>
Astral-PE can modify PE headers in ways that break third-party parsers but keep the Windows loader happy. Techniques include zeroing non-essential fields, corrupting the Rich header, and manipulating the DOS stub.
</details>

<details class="hint-box"><summary>Hint 2</summary>
The EDR validates <code>e_lfanew <= 1024*1024</code> — what if it pointed to a valid but unusual location? The EDR also assumes section headers are contiguous — what if they're not?
</details>

<details class="hint-box"><summary>Hint 3</summary>
The Windows PE loader only needs a small subset of PE fields to work. The EDR parser checks MZ magic, PE signature, and reads sections linearly. Corrupting the NumberOfSections field, Optional Header size, or inserting garbage between headers will crash the parser while Windows happily loads the binary.
</details>
