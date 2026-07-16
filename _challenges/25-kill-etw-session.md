---
layout: default
title: "Challenge 25: Kill the Trace Session"
difficulty: easy
category: "ETW Bypass"
rule: 8
---

# Challenge 25: Kill the Trace Session

<span class="badge badge-easy">Easy</span>
<span class="badge badge-category">ETW Bypass</span>

## Objective

Terminate the MostShittyEDR's ETW trace session to blind its telemetry pipeline.

## Background

The MostShittyEDR agent starts an ETW (Event Tracing for Windows) trace session to collect detection events as telemetry. Real EDRs use ETW extensively — it's the primary mechanism for both user-mode and kernel-mode event collection on Windows.

ETW trace sessions are managed by **controllers** — any process with sufficient privileges can query, modify, or stop a trace session using tools like `logman.exe` or the ETW controller APIs.

## The Weakness

The agent uses a **hardcoded session name**: `MostShittyEDR-Telemetry`. This name is:
- Discoverable by enumerating active trace sessions
- Stoppable by any process with admin privileges
- Not re-created if killed (the agent checks periodically, but there's a gap)

## Rules

1. The EDR agent must be running with `--verbose` and admin privileges
2. Terminate the ETW trace session so the agent can no longer emit telemetry events
3. Rule 8 will detect the session loss — but only on the next check cycle

## Hints

<div class="hint-box">
<details>
<summary>Hint 1</summary>
List all active ETW trace sessions on the system. What tool shows you running sessions?
</details>
</div>

<div class="hint-box">
<details>
<summary>Hint 2</summary>
<code>logman query -ets</code> lists all active Event Trace Sessions. Look for the MostShittyEDR session name.
</details>
</div>

<div class="hint-box">
<details>
<summary>Hint 3</summary>
<code>logman stop "SESSION_NAME" -ets</code> terminates a running trace session.
</details>
</div>
