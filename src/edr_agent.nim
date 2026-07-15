## MostShittyEDR - EDR Bypass Lab
## A deliberately weak Endpoint Detection & Response agent
## for learning EDR evasion techniques.
##
## Usage: edr_agent.exe [--verbose] [--no-kill] [--interval MS]
##
## This agent monitors new processes via user-mode polling and
## applies intentionally weak detection rules. Each weakness
## maps to a bypass challenge.

import winim/lean
import std/[os, strutils, times, sets, parseopt]

# ============================================================
# Constants
# ============================================================

const
  Version = "1.0.0"
  DefaultPollMs = 500

  # Windows console color attributes
  clReset   = 0x07'u16
  clRed     = 0x0C'u16
  clGreen   = 0x0A'u16
  clYellow  = 0x0E'u16
  clCyan    = 0x0B'u16
  clMagenta = 0x0D'u16
  clWhite   = 0x0F'u16

# ============================================================
# Types
# ============================================================

type
  Severity = enum
    sInfo     = "INFO"
    sWarning  = "WARN"
    sAlert    = "ALERT"
    sCritical = "CRIT"

  ProcessInfo = object
    pid: DWORD
    parentPid: DWORD
    exeName: string
    commandLine: string

  Detection = object
    ruleName: string
    ruleId: int
    severity: Severity
    description: string

  Config = object
    verbose: bool
    noKill: bool
    pollInterval: int

# ============================================================
# Globals
# ============================================================

var
  gRunning = true
  gKnownPids: HashSet[DWORD]
  gStats = (seen: 0, detections: 0, kills: 0)

let hStdout = GetStdHandle(STD_OUTPUT_HANDLE)

# ============================================================
# Console helpers
# ============================================================

proc setColor(c: uint16) =
  SetConsoleTextAttribute(hStdout, WORD(c))

proc ts(): string =
  now().format("HH:mm:ss'.'fff")

proc colorLine(c: uint16, msg: string) =
  setColor(c)
  echo msg
  setColor(clReset)

# ============================================================
# Ctrl+C handler
# ============================================================

proc ctrlHandler(ctrlType: DWORD): WINBOOL {.stdcall.} =
  if ctrlType == CTRL_C_EVENT or ctrlType == CTRL_BREAK_EVENT:
    gRunning = false
    return WINBOOL(1)
  return WINBOOL(0)

# ============================================================
# Wide string helper
# ============================================================

proc wcharToStr(arr: openArray[WCHAR]): string =
  result = ""
  for c in arr:
    if c == 0: break
    if int(c) < 128:
      result.add(chr(int(c)))
    else:
      result.add('?')

# ============================================================
# Process enumeration via CreateToolhelp32Snapshot
# WEAKNESS: Polling-based, processes that start and exit
#           between polls are invisible (Challenge 10)
# ============================================================

proc enumerateProcesses(): seq[ProcessInfo] =
  result = @[]
  let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
  if snap == INVALID_HANDLE_VALUE: return
  defer: CloseHandle(snap)

  var pe: PROCESSENTRY32W
  pe.dwSize = DWORD(sizeof(PROCESSENTRY32W))

  if Process32FirstW(snap, addr pe) == 0: return

  while true:
    result.add ProcessInfo(
      pid: pe.th32ProcessID,
      parentPid: pe.th32ParentProcessID,
      exeName: wcharToStr(pe.szExeFile)
    )
    if Process32NextW(snap, addr pe) == 0: break

# ============================================================
# Command line reading via PEB
# WEAKNESS: Only works for 64-bit processes (Challenge 17)
# WEAKNESS: Fails for elevated/protected processes (Challenge 16)
# WEAKNESS: ASCII-only conversion, Unicode chars become '?' (Challenge 18)
# ============================================================

type
  PROCESS_BASIC_INFORMATION = object
    Reserved1: PVOID
    PebBaseAddress: PVOID
    Reserved2: array[2, PVOID]
    UniqueProcessId: ULONG_PTR
    Reserved3: PVOID

proc NtQueryInformationProcess(
  ProcessHandle: HANDLE,
  ProcessInformationClass: ULONG,
  ProcessInformation: PVOID,
  ProcessInformationLength: ULONG,
  ReturnLength: ptr ULONG
): LONG {.stdcall, dynlib: "ntdll.dll", importc.}

proc getCommandLine(pid: DWORD): string =
  result = ""
  if pid == 0 or pid == 4: return

  let hProc = OpenProcess(
    PROCESS_QUERY_INFORMATION or PROCESS_VM_READ,
    WINBOOL(0), pid)
  if hProc == 0: return
  defer: CloseHandle(hProc)

  var pbi: PROCESS_BASIC_INFORMATION
  var retLen: ULONG = 0

  if NtQueryInformationProcess(hProc, 0, addr pbi,
      ULONG(sizeof(pbi)), addr retLen) != 0:
    return

  if pbi.PebBaseAddress == nil: return

  var procParams: uint64
  var bytesRead: SIZE_T = 0
  let pebAddr = cast[uint64](pbi.PebBaseAddress)

  # ProcessParameters at PEB + 0x20 (64-bit)
  if ReadProcessMemory(hProc,
      cast[LPCVOID](pebAddr + 0x20'u64),
      addr procParams, SIZE_T(sizeof(procParams)),
      addr bytesRead) == 0:
    return

  # CommandLine UNICODE_STRING at ProcessParameters + 0x70
  var cmdLineLen: USHORT = 0
  if ReadProcessMemory(hProc,
      cast[LPCVOID](procParams + 0x70'u64),
      addr cmdLineLen, SIZE_T(sizeof(cmdLineLen)),
      addr bytesRead) == 0:
    return

  if cmdLineLen == 0: return

  # Buffer pointer at ProcessParameters + 0x78
  var cmdLineBuf: uint64 = 0
  if ReadProcessMemory(hProc,
      cast[LPCVOID](procParams + 0x78'u64),
      addr cmdLineBuf, SIZE_T(sizeof(cmdLineBuf)),
      addr bytesRead) == 0:
    return

  if cmdLineBuf == 0: return

  var buf = newSeq[byte](int(cmdLineLen) + 2)
  if ReadProcessMemory(hProc,
      cast[LPCVOID](cmdLineBuf),
      addr buf[0], SIZE_T(cmdLineLen),
      addr bytesRead) == 0:
    return

  # WEAKNESS: ASCII-only conversion, drops Unicode (Challenge 18)
  let wcharCount = int(cmdLineLen) div 2
  for i in 0 ..< wcharCount:
    let lo = buf[i * 2]
    let hi = buf[i * 2 + 1]
    if hi == 0 and lo < 128:
      result.add(chr(lo))
    else:
      result.add('?')

# ============================================================
# DETECTION RULE 1: Process Name Blacklist
#
# WEAKNESS: Case-SENSITIVE comparison (Challenge 1, 2)
# WEAKNESS: Exact name match only, renaming bypasses (Challenge 3)
# WEAKNESS: Hardcoded list, unlisted tools pass (Challenge 4)
# WEAKNESS: No path analysis, only filename (Challenge 5)
# ============================================================

const BlacklistedProcesses = [
  "mimikatz.exe",
  "procdump.exe",
  "procdump64.exe",
  "dumpert.exe",
  "nanodump.exe",
  "rubeus.exe",
  "seatbelt.exe",
  "sharphound.exe",
  "lazagne.exe",
  "safetykatz.exe",
  "bloodhound.exe",
  "notepad.exe"
]

proc ruleProcessBlacklist(info: ProcessInfo): seq[Detection] =
  result = @[]
  # BUG: case-sensitive! "Mimikatz.exe" != "mimikatz.exe"
  for name in BlacklistedProcesses:
    if info.exeName == name:
      result.add Detection(
        ruleName: "BLACKLISTED_PROCESS",
        ruleId: 1,
        severity: sCritical,
        description: "Blacklisted process detected: " & info.exeName
      )
      return

# ============================================================
# DETECTION RULE 2: Command Line Keyword Detection
#
# WEAKNESS: No deobfuscation - carets, env vars bypass (Challenge 6, 7)
# WEAKNESS: toLowerAscii only handles bytes 0x41-0x5A (Challenge 18)
# WEAKNESS: Simple substring match, no context (Challenge 8)
# ============================================================

const SuspiciousKeywords = [
  "mimikatz",
  "sekurlsa",
  "kerberos::list",
  "invoke-mimikatz",
  "invoke-expression",
  "downloadstring",
  "webclient",
  "-dumpcreds",
  "-dcsync",
  "dump lsass",
  "minidump lsass",
  "comsvcs.dll"
]

proc ruleSuspiciousKeywords(info: ProcessInfo): seq[Detection] =
  result = @[]
  let cmd = info.commandLine.toLowerAscii()
  for kw in SuspiciousKeywords:
    if kw in cmd:
      result.add Detection(
        ruleName: "SUSPICIOUS_CMDLINE",
        ruleId: 2,
        severity: sCritical,
        description: "Suspicious keyword in command line: " & kw
      )
      return

# ============================================================
# DETECTION RULE 3: Reconnaissance Command Detection
#
# WEAKNESS: Detects but result is DISCARDED - never blocks!
#           (Challenge 9)
# WEAKNESS: Only checks known commands (Challenge 12)
# ============================================================

const ReconCommands = [
  "whoami",
  "net user",
  "net group",
  "net localgroup",
  "net view",
  "net share",
  "nltest /dclist",
  "dsquery",
  "gpresult",
  "ipconfig /all",
  "systeminfo",
  "arp -a",
  "netstat -an"
]

proc ruleReconDetection(info: ProcessInfo): seq[Detection] =
  result = @[]
  let cmd = info.commandLine.toLowerAscii()
  for recon in ReconCommands:
    if recon in cmd:
      result.add Detection(
        ruleName: "RECON_ACTIVITY",
        ruleId: 3,
        severity: sWarning,
        description: "Reconnaissance command: " & recon
      )
      return

# ============================================================
# DETECTION RULE 4: LSASS Dump Tool Detection
#
# WEAKNESS: Requires BOTH tool name AND "lsass" keyword (Challenge 13)
# WEAKNESS: Tool name is case-insensitive but checked via
#           contains, not suffix (Challenge 14)
# ============================================================

const LsassDumpIndicators = [
  "procdump",
  "sqldumper",
  "dumpert",
  "nanodump",
  "comsvcs",
  "minidumpwritedump",
  "dbghelp",
  "dbgcore"
]

proc ruleLsassDump(info: ProcessInfo): seq[Detection] =
  result = @[]
  let nameLower = info.exeName.toLowerAscii()
  let cmdLower = info.commandLine.toLowerAscii()

  for tool in LsassDumpIndicators:
    if tool in nameLower or tool in cmdLower:
      # WEAKNESS: requires "lsass" keyword - omitting it bypasses
      if "lsass" in cmdLower or "-ma" in cmdLower:
        result.add Detection(
          ruleName: "LSASS_DUMP",
          ruleId: 4,
          severity: sCritical,
          description: "LSASS dump attempt via " & tool
        )
        return

# ============================================================
# DETECTION RULE 5: Suspicious PowerShell Execution
#
# WEAKNESS: Only checks "powershell.exe", not "pwsh.exe" or
#           other hosts (Challenge 15)
# WEAKNESS: Short flags like "-e" cause false positives but
#           "-EncodedCommand" with mixed case bypasses (Challenge 8)
# ============================================================

const SuspiciousPSFlags = [
  "-encodedcommand",
  "-enc ",
  "-windowstyle hidden",
  "bypass",
  "-noprofile",
  "iex(",
  "iex (",
  "invoke-expression"
]

proc rulePowerShell(info: ProcessInfo): seq[Detection] =
  result = @[]
  # WEAKNESS: only detects powershell.exe, not pwsh.exe
  if "powershell.exe" notin info.exeName.toLowerAscii():
    return

  let cmdLower = info.commandLine.toLowerAscii()
  for flag in SuspiciousPSFlags:
    if flag in cmdLower:
      result.add Detection(
        ruleName: "SUSPICIOUS_POWERSHELL",
        ruleId: 5,
        severity: sAlert,
        description: "Suspicious PowerShell flags: " & flag
      )
      return

# ============================================================
# DETECTION RULE 6: Hash-Based Detection (Security Theater)
#
# WEAKNESS: The hash database is EMPTY. This rule exists only
#           to look impressive in the feature list. It will
#           never detect anything. (Challenge 20)
# ============================================================

let KnownMalwareHashes: seq[string] = @[]

proc ruleHashCheck(info: ProcessInfo): seq[Detection] =
  result = @[]
  # "Checking" known malware hashes...
  for h in KnownMalwareHashes:
    discard h
  # Always returns empty - pure security theater

# ============================================================
# Analysis Engine
# ============================================================

proc analyzeProcess(info: ProcessInfo, cfg: Config): seq[Detection] =
  var enriched = info
  enriched.commandLine = getCommandLine(info.pid)

  result = @[]
  result.add ruleProcessBlacklist(enriched)
  result.add ruleSuspiciousKeywords(enriched)

  # WEAKNESS: recon detection runs but result is discarded!
  discard ruleReconDetection(enriched)

  result.add ruleLsassDump(enriched)
  result.add rulePowerShell(enriched)

  # WEAKNESS: hash check runs but database is empty
  discard ruleHashCheck(enriched)

# ============================================================
# Response Engine
# ============================================================

proc killProcess(pid: DWORD): bool =
  let h = OpenProcess(PROCESS_TERMINATE, WINBOOL(0), pid)
  if h == 0: return false
  defer: CloseHandle(h)
  return TerminateProcess(h, 1) != 0

proc respond(info: ProcessInfo, detections: seq[Detection], cfg: Config) =
  for det in detections:
    inc gStats.detections

    let color = case det.severity
      of sCritical: clRed
      of sAlert:    clYellow
      of sWarning:  clCyan
      of sInfo:     clReset

    let icon = case det.severity
      of sCritical: "[CRITICAL]"
      of sAlert:    "[ALERT]   "
      of sWarning:  "[WARN]    "
      of sInfo:     "[INFO]    "

    setColor(color)
    echo "[", ts(), "] ", icon, " ", det.description
    echo "             PID: ", info.pid, " | Image: ", info.exeName

    if det.severity == sCritical and not cfg.noKill:
      setColor(clRed)
      echo "             [ACTION] Terminating PID ", info.pid
      if killProcess(info.pid):
        inc gStats.kills
        setColor(clGreen)
        echo "             [+] Process terminated successfully"
      else:
        setColor(clRed)
        echo "             [-] Termination failed (err=", GetLastError(), ")"

    setColor(clReset)

# ============================================================
# Banner
# ============================================================

proc displayBanner() =
  setColor(clCyan)
  echo ""
  echo r"  __  __         _   ___ _    _ _   _          ___ ___  ___  "
  echo r" |  \/  |___ ___| |_/ __| |_ (_) |_| |_ _  _ | __|   \| _ \"
  echo r" | |\/| / _ (_-<  _\__ \ ' \| |  _|  _| || | | _|| |) |   /"
  echo r" |_|  |_\___/__/\__|___/_||_|_|\__|\__|\_, | |___|___/|_|_\"
  echo r"                                        |__/                "
  setColor(clYellow)
  echo ""
  echo "  The World's Most Intentionally Terrible EDR"
  echo "  \"If you can't bypass this, you definitely need more practice\""
  echo ""
  setColor(clGreen)
  echo "  Version: ", Version
  echo "  Mode:    User-mode process monitoring (no driver required)"
  echo ""
  setColor(clCyan)
  echo "  Detection Rules:"
  echo "    [1] Process Name Blacklist    (", BlacklistedProcesses.len, " entries)"
  echo "    [2] Command Line Keywords     (", SuspiciousKeywords.len, " patterns)"
  echo "    [3] Recon Command Detection   (", ReconCommands.len, " commands) [WARN ONLY]"
  echo "    [4] LSASS Dump Detection      (", LsassDumpIndicators.len, " indicators)"
  echo "    [5] PowerShell Flag Analysis  (", SuspiciousPSFlags.len, " flags)"
  echo "    [6] Hash-Based Detection      (", KnownMalwareHashes.len, " hashes) [EMPTY]"
  echo ""
  setColor(clReset)

# ============================================================
# Help
# ============================================================

proc showHelp() =
  echo "MostShittyEDR v", Version, " - EDR Bypass Lab"
  echo ""
  echo "Usage: edr_agent.exe [OPTIONS]"
  echo ""
  echo "Options:"
  echo "  --verbose, -v      Show all new processes (not just detections)"
  echo "  --no-kill, -n      Detect but don't terminate processes"
  echo "  --interval MS      Set polling interval in ms (default: ", DefaultPollMs, ")"
  echo "  --help, -h         Show this help"
  echo ""
  echo "Challenges: See challenges/ directory or visit the GitHub Pages site"

# ============================================================
# Command line parsing
# ============================================================

proc parseConfig(): Config =
  result = Config(
    verbose: false,
    noKill: false,
    pollInterval: DefaultPollMs
  )

  var p = initOptParser()
  while true:
    p.next()
    case p.kind
    of cmdEnd: break
    of cmdShortOption, cmdLongOption:
      case p.key.toLowerAscii()
      of "verbose", "v": result.verbose = true
      of "no-kill", "n": result.noKill = true
      of "interval", "i":
        result.pollInterval = parseInt(p.val)
        if result.pollInterval < 50:
          result.pollInterval = 50
      of "help", "h":
        showHelp()
        quit(0)
      else:
        echo "Unknown option: ", p.key
        quit(1)
    of cmdArgument:
      discard

# ============================================================
# Main
# ============================================================

proc main() =
  let cfg = parseConfig()

  displayBanner()

  SetConsoleCtrlHandler(ctrlHandler, WINBOOL(1))

  # Take initial process snapshot (don't analyze existing processes)
  # WEAKNESS: processes running before EDR starts are invisible (Challenge 11)
  let initial = enumerateProcesses()
  gKnownPids = initHashSet[DWORD]()
  for p in initial:
    gKnownPids.incl(p.pid)

  setColor(clCyan)
  echo "[", ts(), "] Initial snapshot: ", gKnownPids.len, " processes"
  echo "[", ts(), "] Poll interval: ", cfg.pollInterval, "ms"
  if cfg.noKill:
    setColor(clYellow)
    echo "[", ts(), "] Kill mode: DISABLED (detection only)"
  if cfg.verbose:
    echo "[", ts(), "] Verbose mode: ON"
  setColor(clCyan)
  echo "[", ts(), "] Monitoring for new processes... (Ctrl+C to stop)"
  echo "============================================================"
  setColor(clReset)
  echo ""

  # Main monitoring loop
  while gRunning:
    let current = enumerateProcesses()
    var newKnown = initHashSet[DWORD]()

    for p in current:
      newKnown.incl(p.pid)

      if p.pid notin gKnownPids:
        inc gStats.seen
        let detections = analyzeProcess(p, cfg)

        if detections.len > 0:
          respond(p, detections, cfg)
        elif cfg.verbose:
          setColor(clGreen)
          echo "[", ts(), "] [OK]       ", p.exeName, " (PID: ", p.pid, ")"
          setColor(clReset)

    gKnownPids = newKnown
    Sleep(DWORD(cfg.pollInterval))

  # Shutdown
  echo ""
  setColor(clYellow)
  echo "============================================================"
  echo "[", ts(), "] Shutting down..."
  setColor(clCyan)
  echo "[", ts(), "] Statistics:"
  echo "             Processes seen:  ", gStats.seen
  echo "             Detections:      ", gStats.detections
  echo "             Kills:           ", gStats.kills
  setColor(clGreen)
  echo "[", ts(), "] Shutdown complete"
  setColor(clReset)

main()
