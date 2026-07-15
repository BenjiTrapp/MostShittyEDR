---
title: "Challenge 09: The Useless Rule"
difficulty: easy
category: "Command Line Obfuscation"
target_rule: 3
---

## Objective

Discover why reconnaissance commands like `whoami`, `net user`, `ipconfig /all`, and `systeminfo` are never actually blocked by the EDR.

## Scanner Behavior

Rule 3 detects reconnaissance commands and creates a detection result. But look at how the analysis engine calls it:

```nim
proc analyzeProcess(info: ProcessInfo, cfg: Config): seq[Detection] =
  result = @[]
  result.add ruleProcessBlacklist(enriched)
  result.add ruleSuspiciousKeywords(enriched)

  # WEAKNESS: recon detection runs but result is discarded!
  discard ruleReconDetection(enriched)

  result.add ruleLsassDump(enriched)
  ...
```

## Rules

- Execute at least 3 different reconnaissance commands
- Observe the EDR output - are they detected? Are they blocked?
- Explain why Rule 3 is ineffective

## Hints

<details class="hint-box"><summary>Hint 1</summary>
Read the source code carefully. What does <code>discard</code> do in Nim?
</details>

<details class="hint-box"><summary>Hint 2</summary>
<code>discard</code> evaluates the expression but throws away the return value. The detections are never added to the result list.
</details>

<details class="hint-box"><summary>Hint 3</summary>
Note that "whoami" IS in Rule 2's <code>SuspiciousKeywords</code> list, so it gets caught there. But pure recon commands like "ipconfig /all" or "systeminfo" only match Rule 3, which is discarded.
</details>
