---
layout: default
title: "Challenge 27: Provider Unregistration"
difficulty: medium
category: "ETW Bypass"
rule: 8
---

# Challenge 27: Provider Unregistration

<span class="badge badge-medium">Medium</span>
<span class="badge badge-category">ETW Bypass</span>

## Objective

Disable the MostShittyEDR's ETW provider from the trace session without killing the session itself, so Rule 8's session health check continues to pass.

## Background

ETW trace sessions and providers are separate concepts:
- A **session** collects events from one or more providers
- A **provider** is registered by an application and emits events
- A **controller** can enable or disable providers within a session

Using the ETW controller APIs, you can selectively disable a specific provider from a session. The session continues to run (healthy), but the provider no longer emits events into it.

## The Weakness

Rule 8 checks two things:
1. Is `EtwEventWrite` patched? (byte check)
2. Is the trace session still running? (session query)

It does **not** check whether the provider is still **enabled** in the session. Disabling the provider leaves both checks green while the telemetry goes dark.

## Rules

1. The EDR agent must be running with ETW enabled and admin privileges
2. Disable the MostShittyEDR provider in the trace session
3. The trace session must continue to exist (Rule 8 session check must pass)
4. Verify no more ETW events are emitted by the agent

## Hints

<div class="hint-box">
<details>
<summary>Hint 1</summary>
The provider GUID is hardcoded: <code>{4D6F7374-5368-6974-7479-454452000000}</code>. You can find it in the binary or in the source code.
</details>
</div>

<div class="hint-box">
<details>
<summary>Hint 2</summary>
<code>logman update trace "SESSION" -p "{GUID}" 0 0 --ets</code> can modify provider settings in a running session. Setting keywords and level to 0 effectively silences the provider.
</details>
</div>

<div class="hint-box">
<details>
<summary>Hint 3</summary>
Alternatively, use <code>EnableTraceEx2</code> with <code>EVENT_CONTROL_CODE_DISABLE_PROVIDER</code> (0) to programmatically disable the provider in the session.
</details>
</div>
