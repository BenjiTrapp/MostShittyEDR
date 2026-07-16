---
title: "Challenge 29: Single-Byte Hash Evasion"
difficulty: easy
category: "Signature Bypass"
target_rule: 6
---

## Objective

Evade Rule 6's SHA256 signature detection by modifying a single byte of the malware binary.

## Prerequisites

Start the EDR with signatures loaded:

```powershell
edr_agent.exe --signatures signatures/malware_hashes.txt --verbose --no-kill
```

## Scanner Behavior

Rule 6 computes SHA256 of the on-disk process image and compares it against loaded signatures:

```nim
proc ruleHashCheck(info: ProcessInfo): seq[Detection] =
  if gSignatureHashes.len == 0: return
  let imgHash = sha256File(info.imagePath)
  if imgHash in gSignatureHashes: ...
```

A single byte change produces a completely different SHA256 hash.

## Rules

- Take any binary whose hash is in the signature file
- Modify exactly one byte (append a null, change a resource, patch a padding byte)
- Run the modified binary — Rule 6 must not trigger

## Hints

<details class="hint-box"><summary>Hint 1</summary>
SHA256 is a cryptographic hash — even a 1-bit change produces an entirely different digest.
</details>

<details class="hint-box"><summary>Hint 2</summary>
Try: <code>echo. >> malware.exe</code> to append a newline byte. The binary still runs, but the hash is now different.
</details>

<details class="hint-box"><summary>Hint 3</summary>
Any PE resource editor, hex editor, or even just appending junk data to the file will change the SHA256. The binary remains functional because the PE loader ignores trailing data.
</details>
