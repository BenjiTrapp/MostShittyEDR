---
title: "Solution 20: The Empty Hash Database"
difficulty: easy
category: "Advanced Bypass"
---

[Back to Challenge]({{ '/challenges/20-empty-hash-database/' | relative_url }})

## Overview

Rule 6 is security theater: the hash database is empty AND the result is discarded. It provides zero protection.

## Solution

```powershell
# Any binary passes Rule 6 - there is nothing to bypass
# Run any malware sample and Rule 6 will not detect it
.\totally-not-malware.exe
.\known-bad-hash.exe
.\anything.exe
```

## Why It Works

Two independent bugs make Rule 6 completely useless:

**Bug 1: Empty database**
```nim
let KnownMalwareHashes: seq[string] = @[]  # zero entries
```
The `for h in KnownMalwareHashes` loop iterates zero times. No hash is ever compared.

**Bug 2: Result discarded**
```nim
discard ruleHashCheck(enriched)  # even if it returned something...
```
Even if the database had entries and a match was found, the `discard` keyword throws away the detection result. It is never added to the response list.

## Real-World Lesson

This demonstrates two common issues in security software:
1. **Incomplete implementation**: Features that exist in code but have empty data
2. **Dead code**: Logic that executes but whose output is never used

Both create a false sense of security. The feature appears in the detection rule list ("Hash-Based Detection") but provides zero protection.
