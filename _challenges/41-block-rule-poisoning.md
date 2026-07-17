---
title: "Challenge 41: Block Rule Poisoning"
difficulty: medium
category: "IOCTL Abuse"
---

# Challenge 41: Block Rule Poisoning

**Difficulty:** Medium | **Category:** IOCTL Abuse | **Target:** Block Rule Table

## Objective

Use the driver's own `IOCTL_ADD_BLOCK_RULE` to inject a rule that blocks the EDR agent itself from restarting — weaponizing the kernel's process-deny mechanism against the EDR.

## Background

The MostShittyEDR driver maintains a kernel-level block rule table (up to 64 entries). When `ProcessCallback` fires for a new process, it checks every rule — if a rule matches the image name suffix and command-line substring, `CreationStatus` is set to `STATUS_ACCESS_DENIED` and the process never starts.

The `IOCTL_ADD_BLOCK_RULE` (`0x222008`) allows pushing new rules. Since the device has no access control, an attacker can push rules that block anything — including the EDR agent itself or critical system processes.

## Weakness Exploited

1. **No authentication on `ADD_BLOCK_RULE`**: Any process can push block rules to the kernel
2. **No rule validation**: The driver doesn't check if a rule would block its own agent or system-critical processes
3. **Rules survive agent death**: After killing the agent (Challenge 40), poisoned rules remain in the kernel — the agent can never restart
4. **No duplicate detection**: The same rule can be pushed 64 times, filling all slots
5. **Combined with `CLEAR_BLOCK_RULES`**: The attacker can first clear legitimate rules, then push malicious ones

## Hints

1. Open `\\.\MostShittyEDR` and send `IOCTL_ADD_BLOCK_RULE` (`0x222008`)
2. The input buffer is a `BLOCK_RULE_ENTRY` struct: `{ ImageSuffix: WCHAR[260], CmdLineSubstr: WCHAR[512] }`
3. Set `ImageSuffix = "edr_agent.exe"` and `CmdLineSubstr = ""` (empty = wildcard) to block the agent
4. The kernel denies process creation at callback time — the agent binary never executes
5. For maximum damage: first `IOCTL_CLEAR_BLOCK_RULES` to remove legitimate rules, then push poisoned rules, then `IOCTL_KILL_PROCESS` to kill the running agent
6. Bonus: push a rule with `ImageSuffix = ""` and `CmdLineSubstr = ""` — both wildcards match everything, blocking ALL processes on the system (careful: this is a DoS)

## Success Criteria

- A block rule targeting `edr_agent.exe` is pushed to the kernel
- After killing the agent, attempting to restart it fails with "Access Denied"
- The block persists until the driver is unloaded or `CLEAR_BLOCK_RULES` is called

[View Solution]({{ '/solutions/41-block-rule-poisoning/' | relative_url }})
