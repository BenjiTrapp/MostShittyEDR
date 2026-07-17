---
layout: default
title: "Challenges"
permalink: /challenges/
---

# EDR Bypass Challenges

42 challenges across 11 categories. Start with Easy and work your way up.

## Category 1: Process Name Evasion

<div class="challenge-grid">

<a href="{{ '/challenges/01-binary-rename/' | relative_url }}" class="challenge-card">
<span class="badge badge-easy">Easy</span>
<h3>01 - Binary Rename</h3>
<p>Rename a blacklisted tool to bypass process name detection</p>
</a>

<a href="{{ '/challenges/02-case-sensitivity/' | relative_url }}" class="challenge-card">
<span class="badge badge-easy">Easy</span>
<h3>02 - Case Sensitivity Exploit</h3>
<p>Exploit case-sensitive string comparison in the blacklist</p>
</a>

<a href="{{ '/challenges/03-copy-and-rename/' | relative_url }}" class="challenge-card">
<span class="badge badge-easy">Easy</span>
<h3>03 - Copy and Rename</h3>
<p>Copy a tool to a new filename to avoid detection</p>
</a>

<a href="{{ '/challenges/04-unlisted-tool/' | relative_url }}" class="challenge-card">
<span class="badge badge-easy">Easy</span>
<h3>04 - Unlisted Tool</h3>
<p>Use a tool that isn't in the hardcoded blacklist</p>
</a>

</div>

## Category 2: Command Line Obfuscation

<div class="challenge-grid">

<a href="{{ '/challenges/05-path-manipulation/' | relative_url }}" class="challenge-card">
<span class="badge badge-easy">Easy</span>
<h3>05 - Path Manipulation</h3>
<p>Use path tricks to confuse the filename check</p>
</a>

<a href="{{ '/challenges/06-caret-insertion/' | relative_url }}" class="challenge-card">
<span class="badge badge-easy">Easy</span>
<h3>06 - Caret Insertion</h3>
<p>Use cmd.exe escape characters to break keyword matching</p>
</a>

<a href="{{ '/challenges/07-env-variable-substitution/' | relative_url }}" class="challenge-card">
<span class="badge badge-medium">Medium</span>
<h3>07 - Environment Variable Substitution</h3>
<p>Use environment variables to hide command keywords</p>
</a>

<a href="{{ '/challenges/08-base64-encoding/' | relative_url }}" class="challenge-card">
<span class="badge badge-medium">Medium</span>
<h3>08 - Base64 Encoded Commands</h3>
<p>Encode commands to bypass keyword detection</p>
</a>

<a href="{{ '/challenges/09-the-useless-rule/' | relative_url }}" class="challenge-card">
<span class="badge badge-easy">Easy</span>
<h3>09 - The Useless Rule</h3>
<p>Discover why reconnaissance commands are never blocked</p>
</a>

</div>

## Category 3: Process Monitoring Bypass

<div class="challenge-grid">

<a href="{{ '/challenges/10-timing-attack/' | relative_url }}" class="challenge-card">
<span class="badge badge-medium">Medium</span>
<h3>10 - Timing Attack</h3>
<p>Exploit the polling interval to execute undetected</p>
</a>

<a href="{{ '/challenges/11-pre-existing-process/' | relative_url }}" class="challenge-card">
<span class="badge badge-easy">Easy</span>
<h3>11 - Pre-Existing Process</h3>
<p>Be running before the EDR starts monitoring</p>
</a>

<a href="{{ '/challenges/12-living-off-the-land/' | relative_url }}" class="challenge-card">
<span class="badge badge-medium">Medium</span>
<h3>12 - Living Off The Land</h3>
<p>Use built-in tools and alternative commands</p>
</a>

<a href="{{ '/challenges/13-lsass-without-keywords/' | relative_url }}" class="challenge-card">
<span class="badge badge-medium">Medium</span>
<h3>13 - LSASS Without Keywords</h3>
<p>Dump LSASS without triggering keyword detection</p>
</a>

<a href="{{ '/challenges/14-tool-rename-lsass/' | relative_url }}" class="challenge-card">
<span class="badge badge-medium">Medium</span>
<h3>14 - Tool Rename for LSASS</h3>
<p>Rename dump tools to bypass the dual-condition rule</p>
</a>

</div>

## Category 4: Execution Evasion

<div class="challenge-grid">

<a href="{{ '/challenges/15-alternative-powershell/' | relative_url }}" class="challenge-card">
<span class="badge badge-medium">Medium</span>
<h3>15 - Alternative PowerShell Host</h3>
<p>Execute PowerShell without powershell.exe</p>
</a>

<a href="{{ '/challenges/16-elevated-process/' | relative_url }}" class="challenge-card">
<span class="badge badge-medium">Medium</span>
<h3>16 - Elevated Process Evasion</h3>
<p>Exploit the EDR's inability to read elevated processes</p>
</a>

<a href="{{ '/challenges/17-32bit-evasion/' | relative_url }}" class="challenge-card">
<span class="badge badge-medium">Medium</span>
<h3>17 - 32-Bit Process Evasion</h3>
<p>Use a 32-bit process to break PEB reading</p>
</a>

<a href="{{ '/challenges/18-unicode-names/' | relative_url }}" class="challenge-card">
<span class="badge badge-hard">Hard</span>
<h3>18 - Unicode Process Names</h3>
<p>Exploit ASCII-only string handling with Unicode characters</p>
</a>

</div>

## Category 5: Advanced Bypass

<div class="challenge-grid">

<a href="{{ '/challenges/19-parent-pid-spoofing/' | relative_url }}" class="challenge-card">
<span class="badge badge-hard">Hard</span>
<h3>19 - Parent PID Spoofing</h3>
<p>Spoof the parent process ID to confuse tracking</p>
</a>

<a href="{{ '/challenges/20-empty-hash-database/' | relative_url }}" class="challenge-card">
<span class="badge badge-easy">Easy</span>
<h3>20 - The Empty Hash Database</h3>
<p>Discover that Rule 6 has no signatures without --signatures flag</p>
</a>

</div>

## Category 6: API Hook Evasion

Requires `--profile` flag (e.g. `--profile crowdstrike`). These challenges target Rule 7's static import analysis using real EDR hook profiles from [Mr-Un1k0d3r/EDRs](https://github.com/Mr-Un1k0d3r/EDRs).

<div class="challenge-grid">

<a href="{{ '/challenges/21-dynamic-api-resolution/' | relative_url }}" class="challenge-card">
<span class="badge badge-medium">Medium</span>
<h3>21 - Dynamic API Resolution</h3>
<p>Use GetProcAddress to resolve hooked APIs at runtime instead of static imports</p>
</a>

<a href="{{ '/challenges/22-dll-proxy-call/' | relative_url }}" class="challenge-card">
<span class="badge badge-medium">Medium</span>
<h3>22 - DLL Proxy Call</h3>
<p>Move the hooked API call into a DLL that the scanner doesn't inspect</p>
</a>

<a href="{{ '/challenges/23-direct-syscalls/' | relative_url }}" class="challenge-card">
<span class="badge badge-hard">Hard</span>
<h3>23 - Direct Syscalls</h3>
<p>Skip ntdll.dll entirely using Hell's Gate direct syscall technique</p>
</a>

<a href="{{ '/challenges/24-ntdll-unhooking/' | relative_url }}" class="challenge-card">
<span class="badge badge-hard">Hard</span>
<h3>24 - ntdll.dll Unhooking</h3>
<p>Restore ntdll.dll from disk to remove all userland hooks undetected</p>
</a>

</div>

## Category 7: ETW Bypass

Target the EDR's ETW telemetry pipeline. The agent registers a custom ETW provider and trace session — blind it using session manipulation, memory patching, or patchless hooking techniques. See [Breaking ETW and EDR](https://benjitrapp.github.io/attacks/2024-02-11-offensive-etw/) and [ETW-TI Deep Dive](https://benjitrapp.github.io/defenses/2026-06-19-etw-ti/) for background.

<div class="challenge-grid">

<a href="{{ '/challenges/25-kill-etw-session/' | relative_url }}" class="challenge-card">
<span class="badge badge-easy">Easy</span>
<h3>25 - Kill the Trace Session</h3>
<p>Stop the hardcoded ETW trace session to blind the EDR's telemetry</p>
</a>

<a href="{{ '/challenges/26-patch-etwwrite/' | relative_url }}" class="challenge-card">
<span class="badge badge-medium">Medium</span>
<h3>26 - Patch EtwEventWrite</h3>
<p>Patch ntdll!EtwEventWrite to silently disable all user-mode ETW without triggering Rule 8</p>
</a>

<a href="{{ '/challenges/27-provider-unregistration/' | relative_url }}" class="challenge-card">
<span class="badge badge-medium">Medium</span>
<h3>27 - Provider Unregistration</h3>
<p>Disable the EDR's provider from the trace session while keeping the session alive</p>
</a>

<a href="{{ '/challenges/28-hardware-breakpoint-hook/' | relative_url }}" class="challenge-card">
<span class="badge badge-hard">Hard</span>
<h3>28 - Hardware Breakpoint Hook</h3>
<p>Use debug registers and a VEH to intercept EtwEventWrite without modifying code bytes</p>
</a>

</div>

## Category 8: Signature Bypass

Requires `--signatures` flag (e.g. `--signatures signatures/malware_hashes.txt`). These challenges target Rule 6's SHA256-based signature detection.

<div class="challenge-grid">

<a href="{{ '/challenges/29-single-byte-patch/' | relative_url }}" class="challenge-card">
<span class="badge badge-easy">Easy</span>
<h3>29 - Single-Byte Hash Evasion</h3>
<p>Change one byte of a known binary to produce a completely different SHA256 hash</p>
</a>

<a href="{{ '/challenges/30-read-signature-file/' | relative_url }}" class="challenge-card">
<span class="badge badge-easy">Easy</span>
<h3>30 - Read the Signature Database</h3>
<p>The plaintext signature file reveals exactly which hashes the EDR knows</p>
</a>

<a href="{{ '/challenges/31-process-hollowing/' | relative_url }}" class="challenge-card">
<span class="badge badge-hard">Hard</span>
<h3>31 - Process Hollowing vs Hash Check</h3>
<p>Replace process memory after creation — the on-disk image hash stays clean</p>
</a>

<a href="{{ '/challenges/32-recompile-from-source/' | relative_url }}" class="challenge-card">
<span class="badge badge-easy">Easy</span>
<h3>32 - Recompile from Source</h3>
<p>Same source code, different compiler run, completely different hash</p>
</a>

</div>

## Category 9: Packer & PE Evasion

These challenges target Rule 9's PE structure analysis — packer detection, section name matching, and header integrity checks.

<div class="challenge-grid">

<a href="{{ '/challenges/33-upx-section-rename/' | relative_url }}" class="challenge-card">
<span class="badge badge-medium">Medium</span>
<h3>33 - UPX Section Name Rename</h3>
<p>Pack with UPX to change the hash, then rename UPX0/UPX1 sections to evade packer detection</p>
</a>

<a href="{{ '/challenges/34-custom-packer/' | relative_url }}" class="challenge-card">
<span class="badge badge-hard">Hard</span>
<h3>34 - Custom Packer / Crypter</h3>
<p>Build a custom packer with normal section names and no RWX — invisible to static analysis</p>
</a>

<a href="{{ '/challenges/35-pe-header-obfuscation/' | relative_url }}" class="challenge-card">
<span class="badge badge-hard">Hard</span>
<h3>35 - PE Header Obfuscation</h3>
<p>Use Astral-PE style header corruption to crash the EDR's PE parser silently</p>
</a>

<a href="{{ '/challenges/36-runtime-unpacking/' | relative_url }}" class="challenge-card">
<span class="badge badge-hard">Hard</span>
<h3>36 - Runtime Unpacking</h3>
<p>Clean stub on disk, decrypt and execute payload in memory — the EDR never re-scans</p>
</a>

</div>

## Category 10: BYOVD / Kernel Attacks

Bring Your Own Vulnerable Driver — load a legitimately signed driver with dangerous kernel primitives to kill the EDR, remove its callbacks, or blind kernel-level telemetry. Requires Administrator and a vulnerable `.sys` file. See [BYOVD & IOCTL EDR Killer](https://benjitrapp.github.io/attacks/2026-06-24-byovd-ioctl-edr-killer/) for background, [NimBlackout](https://github.com/Helixo32/NimBlackout) and [EDRSandblast](https://github.com/wavestone-cdt/EDRSandblast) for reference implementations.

<div class="challenge-grid">

<a href="{{ '/challenges/37-byovd-kill-edr/' | relative_url }}" class="challenge-card">
<span class="badge badge-hard">Hard</span>
<h3>37 - BYOVD: Kill the EDR</h3>
<p>Load a vulnerable signed driver and terminate the EDR agent from kernel level</p>
</a>

<a href="{{ '/challenges/38-byovd-remove-callbacks/' | relative_url }}" class="challenge-card">
<span class="badge badge-hard">Hard</span>
<h3>38 - BYOVD: Remove Callbacks</h3>
<p>Use kernel R/W to enumerate and zero the driver's process/thread notification callbacks</p>
</a>

<a href="{{ '/challenges/39-byovd-blind-etw-ti/' | relative_url }}" class="challenge-card">
<span class="badge badge-hard">Hard</span>
<h3>39 - BYOVD: Blind ETW-TI</h3>
<p>Disable the kernel-level ETW Threat Intelligence provider via vulnerable driver R/W</p>
</a>

</div>

## Category 11: IOCTL Abuse

The EDR's own kernel driver exposes an unprotected device (`\\.\MostShittyEDR`) — no DACL, no caller verification, `FILE_ANY_ACCESS` on destructive IOCTLs. Weaponize the driver against itself: kill the agent, poison its block rules, or steal its event channel. No external driver needed.

<div class="challenge-grid">

<a href="{{ '/challenges/40-ioctl-hijack-kill/' | relative_url }}" class="challenge-card">
<span class="badge badge-medium">Medium</span>
<h3>40 - IOCTL Hijack: Kill via EDR</h3>
<p>Open the unprotected device and terminate the agent with its own IOCTL_KILL_PROCESS</p>
</a>

<a href="{{ '/challenges/41-block-rule-poisoning/' | relative_url }}" class="challenge-card">
<span class="badge badge-medium">Medium</span>
<h3>41 - Block Rule Poisoning</h3>
<p>Push a kernel block rule targeting edr_agent.exe — it can never restart</p>
</a>

<a href="{{ '/challenges/42-event-channel-dos/' | relative_url }}" class="challenge-card">
<span class="badge badge-medium">Medium</span>
<h3>42 - Event Channel DoS</h3>
<p>Monopolize the single-slot PendingIrp to starve the agent — steal all kernel events</p>
</a>

</div>
