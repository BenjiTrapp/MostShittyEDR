---
title: "Challenge 20: The Empty Hash Database"
difficulty: easy
category: "Advanced Bypass"
target_rule: 6
---

## Objective

Discover that Rule 6 (hash-based detection) is disabled by default — without the `--signatures` flag, it has no hashes to compare against.

## Scanner Behavior

Without `--signatures`, the signature database is empty:

```nim
var gSignatureHashes: seq[string] = @[]

proc ruleHashCheck(info: ProcessInfo): seq[Detection] =
  if gSignatureHashes.len == 0:
    return  # exits immediately — checks nothing
```

The banner displays this openly: `[6] Hash-Based Detection (0 hashes) [EMPTY - use --signatures]`

## Rules

- Start the EDR **without** the `--signatures` flag
- Run any binary (malicious or not)
- Confirm that Rule 6 never triggers
- Explain why the rule is useless without signatures loaded

## Hints

<details class="hint-box"><summary>Hint 1</summary>
Look at the banner output — it tells you exactly how many signatures are loaded.
</details>

<details class="hint-box"><summary>Hint 2</summary>
Without <code>--signatures</code>, <code>gSignatureHashes</code> is an empty sequence. The <code>ruleHashCheck</code> function returns immediately.
</details>

<details class="hint-box"><summary>Hint 3</summary>
Even with <code>--signatures</code> loaded, there are still bypass techniques (Challenges 29-32). But without it, Rule 6 is pure security theater — it appears in the feature list but does absolutely nothing.
</details>
