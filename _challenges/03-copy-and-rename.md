---
title: "Challenge 03: Copy and Rename"
difficulty: easy
category: "Process Name Evasion"
target_rule: 1
---

## Objective

Execute a blacklisted tool by copying it to a completely different name.

## Scanner Behavior

The EDR only checks the process executable name reported by `CreateToolhelp32Snapshot`. It does not verify file hashes, digital signatures, or file contents.

## Rules

- Copy any blacklisted tool to a new, non-blacklisted name
- Execute the copy successfully without detection
- The copy must be functionally identical to the original

## Hints

<details class="hint-box"><summary>Hint 1</summary>
Windows runs executables by their filename, not by their content.
</details>

<details class="hint-box"><summary>Hint 2</summary>
<code>copy notepad.exe editor.exe && editor.exe</code> - is <code>editor.exe</code> in the blacklist?
</details>

<details class="hint-box"><summary>Hint 3</summary>
The EDR has no hash database (Rule 6 is empty). It cannot identify a binary by its content.
</details>
