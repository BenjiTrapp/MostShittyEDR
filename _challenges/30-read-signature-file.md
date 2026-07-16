---
title: "Challenge 30: Read the Signature Database"
difficulty: easy
category: "Signature Bypass"
target_rule: 6
---

## Objective

The signature database is a plaintext file on disk. Read it to learn exactly which hashes the EDR knows about, then avoid them.

## Prerequisites

Start the EDR with signatures loaded:

```powershell
edr_agent.exe --signatures signatures/malware_hashes.txt --verbose --no-kill
```

## Scanner Behavior

The `--signatures` parameter points to a plaintext file. The path is passed on the command line — visible to any process that can enumerate the EDR's command line or simply guess common paths.

```nim
proc loadSignatures(path: string): int =
  for line in lines(path):
    let stripped = line.strip()
    if stripped.startsWith("#"): continue
    ...
```

## Rules

- Find and read the signature file
- Identify all known hashes
- Use this intel to craft or select a binary that avoids every listed hash

## Hints

<details class="hint-box"><summary>Hint 1</summary>
Check the EDR's command line: <code>wmic process where "name='edr_agent.exe'" get commandline</code>
</details>

<details class="hint-box"><summary>Hint 2</summary>
The signature file path is right there in <code>--signatures signatures/malware_hashes.txt</code>. Just read the file.
</details>

<details class="hint-box"><summary>Hint 3</summary>
A real EDR would encrypt or obfuscate its signature database. This one stores SHA256 hashes in plaintext with helpful comments naming each sample.
</details>
