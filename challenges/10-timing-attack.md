---
title: "Challenge 10: Timing Attack"
difficulty: medium
category: "Process Monitoring Bypass"
target_rule: "Architecture"
---

## Objective

Execute a blacklisted command that completes before the EDR's next polling cycle.

## Scanner Behavior

The EDR monitors processes by polling with `CreateToolhelp32Snapshot` at a fixed interval:

```nim
Sleep(DWORD(cfg.pollInterval))  # Default: 500ms
```

A process that starts AND exits between two polls is **never seen** by the EDR.

## Rules

- Execute a blacklisted tool or suspicious command
- The process must complete before the EDR detects it
- The command must produce output proving it ran
- Use the default 500ms polling interval

## Hints

<details class="hint-box"><summary>Hint 1</summary>
The default poll interval is 500ms. Any process that starts and exits in under 500ms might slip through.
</details>

<details class="hint-box"><summary>Hint 2</summary>
Simple commands like <code>whoami</code>, <code>ipconfig</code>, <code>net user</code> typically complete in milliseconds.
</details>

<details class="hint-box"><summary>Hint 3</summary>
The key is that <code>CreateToolhelp32Snapshot</code> is a point-in-time snapshot. A short-lived process between snapshots is invisible. Try running commands via <code>cmd /c</code> which exits quickly.
</details>
