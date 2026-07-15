---
layout: default
title: "Challenges"
---

# EDR Bypass Challenges

20 challenges across 5 categories. Start with Easy and work your way up.

## Category 1: Process Name Evasion

<div class="challenge-grid">

<a href="01-binary-rename/" class="challenge-card">
<span class="badge badge-easy">Easy</span>
<h3>01 - Binary Rename</h3>
<p>Rename a blacklisted tool to bypass process name detection</p>
</a>

<a href="02-case-sensitivity/" class="challenge-card">
<span class="badge badge-easy">Easy</span>
<h3>02 - Case Sensitivity Exploit</h3>
<p>Exploit case-sensitive string comparison in the blacklist</p>
</a>

<a href="03-copy-and-rename/" class="challenge-card">
<span class="badge badge-easy">Easy</span>
<h3>03 - Copy and Rename</h3>
<p>Copy a tool to a new filename to avoid detection</p>
</a>

<a href="04-unlisted-tool/" class="challenge-card">
<span class="badge badge-easy">Easy</span>
<h3>04 - Unlisted Tool</h3>
<p>Use a tool that isn't in the hardcoded blacklist</p>
</a>

</div>

## Category 2: Command Line Obfuscation

<div class="challenge-grid">

<a href="05-path-manipulation/" class="challenge-card">
<span class="badge badge-easy">Easy</span>
<h3>05 - Path Manipulation</h3>
<p>Use path tricks to confuse the filename check</p>
</a>

<a href="06-caret-insertion/" class="challenge-card">
<span class="badge badge-easy">Easy</span>
<h3>06 - Caret Insertion</h3>
<p>Use cmd.exe escape characters to break keyword matching</p>
</a>

<a href="07-env-variable-substitution/" class="challenge-card">
<span class="badge badge-medium">Medium</span>
<h3>07 - Environment Variable Substitution</h3>
<p>Use environment variables to hide command keywords</p>
</a>

<a href="08-base64-encoding/" class="challenge-card">
<span class="badge badge-medium">Medium</span>
<h3>08 - Base64 Encoded Commands</h3>
<p>Encode commands to bypass keyword detection</p>
</a>

<a href="09-the-useless-rule/" class="challenge-card">
<span class="badge badge-easy">Easy</span>
<h3>09 - The Useless Rule</h3>
<p>Discover why reconnaissance commands are never blocked</p>
</a>

</div>

## Category 3: Process Monitoring Bypass

<div class="challenge-grid">

<a href="10-timing-attack/" class="challenge-card">
<span class="badge badge-medium">Medium</span>
<h3>10 - Timing Attack</h3>
<p>Exploit the polling interval to execute undetected</p>
</a>

<a href="11-pre-existing-process/" class="challenge-card">
<span class="badge badge-easy">Easy</span>
<h3>11 - Pre-Existing Process</h3>
<p>Be running before the EDR starts monitoring</p>
</a>

<a href="12-living-off-the-land/" class="challenge-card">
<span class="badge badge-medium">Medium</span>
<h3>12 - Living Off The Land</h3>
<p>Use built-in tools and alternative commands</p>
</a>

<a href="13-lsass-without-keywords/" class="challenge-card">
<span class="badge badge-medium">Medium</span>
<h3>13 - LSASS Without Keywords</h3>
<p>Dump LSASS without triggering keyword detection</p>
</a>

<a href="14-tool-rename-lsass/" class="challenge-card">
<span class="badge badge-medium">Medium</span>
<h3>14 - Tool Rename for LSASS</h3>
<p>Rename dump tools to bypass the dual-condition rule</p>
</a>

</div>

## Category 4: Execution Evasion

<div class="challenge-grid">

<a href="15-alternative-powershell/" class="challenge-card">
<span class="badge badge-medium">Medium</span>
<h3>15 - Alternative PowerShell Host</h3>
<p>Execute PowerShell without powershell.exe</p>
</a>

<a href="16-elevated-process/" class="challenge-card">
<span class="badge badge-medium">Medium</span>
<h3>16 - Elevated Process Evasion</h3>
<p>Exploit the EDR's inability to read elevated processes</p>
</a>

<a href="17-32bit-evasion/" class="challenge-card">
<span class="badge badge-medium">Medium</span>
<h3>17 - 32-Bit Process Evasion</h3>
<p>Use a 32-bit process to break PEB reading</p>
</a>

<a href="18-unicode-names/" class="challenge-card">
<span class="badge badge-hard">Hard</span>
<h3>18 - Unicode Process Names</h3>
<p>Exploit ASCII-only string handling with Unicode characters</p>
</a>

</div>

## Category 5: Advanced Bypass

<div class="challenge-grid">

<a href="19-parent-pid-spoofing/" class="challenge-card">
<span class="badge badge-hard">Hard</span>
<h3>19 - Parent PID Spoofing</h3>
<p>Spoof the parent process ID to confuse tracking</p>
</a>

<a href="20-empty-hash-database/" class="challenge-card">
<span class="badge badge-easy">Easy</span>
<h3>20 - The Empty Hash Database</h3>
<p>Realize there is no hash-based detection at all</p>
</a>

</div>
