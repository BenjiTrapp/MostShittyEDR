---
title: "Solution 09: The Useless Rule"
difficulty: easy
category: "Command Line Obfuscation"
---

[Back to Challenge]({{ '/challenges/09-the-useless-rule/' | relative_url }})

## Overview

Rule 3 (Recon Detection) detects reconnaissance commands but the result is discarded using Nim's `discard` keyword. The detection is computed but never added to the response list.

## Solution

```powershell
# These commands are in Rule 3's list but the rule is discarded:
ipconfig /all
systeminfo
arp -a
netstat -an
gpresult /r
nltest /dclist:

# NOTE: "whoami" and "net user" ARE caught by Rule 2's keyword list!
# Only commands that are exclusively in Rule 3 (not Rule 2) are truly unblocked.
```

## Why It Works

In the analysis engine:

```nim
proc analyzeProcess(info: ProcessInfo, cfg: Config): seq[Detection] =
  result = @[]
  result.add ruleProcessBlacklist(enriched)
  result.add ruleSuspiciousKeywords(enriched)

  discard ruleReconDetection(enriched)  # <-- result thrown away!
  ...
```

The `discard` keyword evaluates `ruleReconDetection(enriched)` (which returns detections) but throws away the return value. The detections are never added to `result`.

## Key Insight

Commands like `ipconfig /all`, `systeminfo`, and `arp -a` are ONLY in Rule 3's list. Since Rule 3 is discarded, they pass through completely undetected. Commands like `whoami` are in BOTH Rule 2 and Rule 3, so they are still caught by Rule 2.
