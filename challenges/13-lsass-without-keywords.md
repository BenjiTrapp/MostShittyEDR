---
title: "Challenge 13: LSASS Without Keywords"
difficulty: medium
category: "Process Monitoring Bypass"
target_rule: 4
---

## Objective

Interact with the LSASS process without including "lsass" in your command line arguments.

## Scanner Behavior

Rule 4 requires **two conditions** to trigger: the tool name must match AND the command line must contain "lsass" or "-ma":

```nim
for tool in LsassDumpIndicators:
  if tool in nameLower or tool in cmdLower:
    if "lsass" in cmdLower or "-ma" in cmdLower:  # BOTH needed!
      ...
```

## Rules

- Reference or interact with the LSASS process
- The command line must not contain the string "lsass"
- The EDR must not trigger a `LSASS_DUMP` detection

## Hints

<details class="hint-box"><summary>Hint 1</summary>
You can reference LSASS by its PID instead of its name. <code>tasklist | findstr lsass</code> gives you the PID (the EDR might catch "lsass" in Rule 2 though).
</details>

<details class="hint-box"><summary>Hint 2</summary>
<code>procdump -ma 612</code> (where 612 is the LSASS PID) - no "lsass" string in the command line!
</details>

<details class="hint-box"><summary>Hint 3</summary>
Even better: use the PID AND rename the tool (Challenge 14) to bypass both conditions of Rule 4.
</details>
