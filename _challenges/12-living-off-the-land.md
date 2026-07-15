---
title: "Challenge 12: Living Off The Land"
difficulty: medium
category: "Process Monitoring Bypass"
target_rule: "2, 3"
---

## Objective

Perform reconnaissance and data gathering using only built-in Windows tools that are not detected by the EDR's keyword rules.

## Scanner Behavior

Rule 2 checks for specific keywords: `whoami`, `net user`, `net group`, etc. Rule 3 checks for additional recon commands but discards the result. Neither rule covers **all** Windows built-in tools.

## Rules

- Gather the current username, domain, IP address, and local administrators
- Use only built-in Windows tools (no third-party software)
- The EDR must not trigger any `SUSPICIOUS_CMDLINE` detections

## Hints

<details class="hint-box"><summary>Hint 1</summary>
There are many ways to get the same information. <code>whoami</code> is not the only way to find your username.
</details>

<details class="hint-box"><summary>Hint 2</summary>
PowerShell cmdlets like <code>Get-WmiObject</code>, <code>[Environment]::UserName</code>, or <code>Get-LocalGroupMember</code> achieve the same results but aren't in the keyword list.
</details>

<details class="hint-box"><summary>Hint 3</summary>
<code>echo %USERNAME%</code>, <code>set USERNAME</code>, <code>wmic useraccount list brief</code> - none of these contain "whoami" or "net user".
</details>
