---
title: "Solution 20: The Empty Hash Database"
difficulty: easy
category: "Advanced Bypass"
---

[Back to Challenge]({{ '/challenges/20-empty-hash-database/' | relative_url }})

## Overview

Without the `--signatures` flag, Rule 6 has zero hashes in its database. It checks nothing and detects nothing.

## Solution

```powershell
# Start EDR without --signatures (the default)
.\edr_agent.exe --verbose --no-kill

# Run anything — Rule 6 never triggers
.\totally-not-malware.exe
.\mimikatz.exe
.\anything.exe
```

## Why It Works

The signature database starts empty:

```nim
var gSignatureHashes: seq[string] = @[]
```

Without `--signatures`, no hashes are ever loaded. The `ruleHashCheck` function returns immediately:

```nim
proc ruleHashCheck(info: ProcessInfo): seq[Detection] =
  if gSignatureHashes.len == 0:
    return  # nothing to check against
```

## Real-World Lesson

This demonstrates a common issue: **opt-in security features**. Rule 6 exists in the code and appears in the banner, creating a false sense of security. But without explicit configuration (`--signatures`), it provides zero protection.

Even with signatures loaded, the detection is still weak — see Challenges 29-32 for bypass techniques targeting the signature matching itself.
