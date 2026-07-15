---
title: "Challenge 20: The Empty Hash Database"
difficulty: easy
category: "Advanced Bypass"
target_rule: 6
---

## Objective

Discover that Rule 6 (hash-based detection) is pure security theater with an empty database.

## Scanner Behavior

Rule 6 claims to check malware hashes but the database is literally empty:

```nim
let KnownMalwareHashes: seq[string] = @[]

proc ruleHashCheck(info: ProcessInfo): seq[Detection] =
  result = @[]
  for h in KnownMalwareHashes:  # iterates over... nothing
    discard h
  # Always returns empty
```

Furthermore, even if the database had entries, the result is **discarded** in the analysis engine:

```nim
discard ruleHashCheck(enriched)  # result thrown away
```

## Rules

- Run any known malware sample or suspicious binary
- Confirm that Rule 6 never triggers
- Explain the two separate reasons why this rule is useless

## Hints

<details class="hint-box"><summary>Hint 1</summary>
Look at the <code>KnownMalwareHashes</code> constant. How many entries does it have?
</details>

<details class="hint-box"><summary>Hint 2</summary>
Even if you added hashes to the database, look at how <code>ruleHashCheck</code> is called in <code>analyzeProcess</code>.
</details>

<details class="hint-box"><summary>Hint 3</summary>
Two bugs: (1) The hash database is empty - zero hashes to compare against. (2) The result of <code>ruleHashCheck</code> is <code>discard</code>ed - even if it found something, the detection would be thrown away. This is double security theater.
</details>
