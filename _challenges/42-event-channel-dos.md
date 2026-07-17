---
title: "Challenge 42: Event Channel DoS"
difficulty: medium
category: "IOCTL Abuse"
---

# Challenge 42: Event Channel DoS

**Difficulty:** Medium | **Category:** IOCTL Abuse | **Target:** Event Delivery

## Objective

Monopolize the driver's single-slot event delivery mechanism so the legitimate EDR agent receives no events — blinding it without killing it or removing callbacks.

## Background

The MostShittyEDR driver uses a **single pending IRP** design for event delivery. When the agent sends `IOCTL_WAIT_FOR_EVENT` (`0x222000`), the IRP is pended in `g_State.PendingIrp`. When a kernel callback fires, the event is copied into the pending IRP and completed. If no IRP is pending, events are queued in memory.

The critical weakness: only ONE IRP can be pending at a time. If a second `WAIT_FOR_EVENT` arrives while one is already pending, the driver returns `STATUS_DEVICE_BUSY`. An attacker who opens the device first and sends `WAIT_FOR_EVENT` before the agent does will **monopolize the event channel** — the agent gets `STATUS_DEVICE_BUSY` on every poll and sees nothing.

## Weakness Exploited

1. **Single PendingIrp slot**: Only one consumer can receive events at a time
2. **No caller identity check**: The driver doesn't verify that the waiting IRP comes from the agent
3. **First-come-first-served**: Whoever sends `WAIT_FOR_EVENT` first wins the slot
4. **No session binding**: The driver doesn't bind to a specific caller on `IRP_MJ_CREATE`
5. **Events flow to the attacker**: The attacker's process receives all kernel events (process/thread creation, LSASS access) — a free telemetry wiretap

## Hints

1. Open `\\.\MostShittyEDR` with `FILE_FLAG_OVERLAPPED` for async I/O
2. Send `IOCTL_WAIT_FOR_EVENT` (`0x222000`) with an `EDR_EVENT`-sized output buffer (1581 bytes)
3. When the IRP completes (event received), immediately send another `WAIT_FOR_EVENT` to re-occupy the slot
4. The agent's `runDriverLoop` will get `ERROR_BUSY` (`werBusy`) on every attempt
5. You're now receiving all kernel events yourself — you can read what the EDR would see
6. Bonus: combine with `IOCTL_CLEAR_BLOCK_RULES` — now the kernel doesn't block anything AND the agent sees nothing

## Success Criteria

- The agent is running in `--driver` mode but receives `STATUS_DEVICE_BUSY` on every poll
- The agent's output shows no `[CREATE]`, `[EXIT]`, or `[THREAD+]` events
- The attacker's tool receives all kernel events in real-time
- The agent process stays alive but is completely blind

[View Solution]({{ '/solutions/42-event-channel-dos/' | relative_url }})
