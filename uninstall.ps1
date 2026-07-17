<#
.SYNOPSIS
    MostShittyEDR complete uninstall script — agent + kernel driver.

.DESCRIPTION
    Stops the EDR agent process, removes the kernel driver service,
    and optionally cleans up build artifacts. Requires Administrator
    for driver removal.

.PARAMETER Agent
    Stop and remove the agent process only.

.PARAMETER Driver
    Stop and remove the kernel driver only.

.PARAMETER Clean
    Also remove build artifacts (edr_agent.exe, nimcache, test binaries).

.PARAMETER Force
    Skip confirmation prompts.

.EXAMPLE
    .\uninstall.ps1                   # Uninstall agent + driver
    .\uninstall.ps1 -Agent            # Stop agent only
    .\uninstall.ps1 -Driver           # Uninstall driver only
    .\uninstall.ps1 -Clean            # Uninstall all + remove build artifacts
    .\uninstall.ps1 -Force            # Skip confirmation
#>

[CmdletBinding(DefaultParameterSetName = 'All')]
param(
    [Parameter(ParameterSetName = 'AgentOnly')]
    [switch]$Agent,

    [Parameter(ParameterSetName = 'DriverOnly')]
    [switch]$Driver,

    [switch]$Clean,
    [switch]$Force
)

$ServiceName = "MostShittyEDR"
$AgentName   = "edr_agent"
$ScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path

# ── Helpers ──────────────────────────────────────────────

function Write-Banner {
    Write-Host ""
    Write-Host "  MostShittyEDR - Uninstaller" -ForegroundColor Red
    Write-Host "  ===========================" -ForegroundColor Red
    Write-Host ""
}

function Test-Administrator {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ── Agent Removal ────────────────────────────────────────

function Stop-Agent {
    Write-Host "  [*] Checking for running agent..." -ForegroundColor Cyan

    $procs = Get-Process -Name $AgentName -ErrorAction SilentlyContinue
    if ($null -eq $procs) {
        Write-Host "      Agent is not running" -ForegroundColor Yellow
        return
    }

    $count = @($procs).Count
    Write-Host "      Found $count agent process(es)" -ForegroundColor Yellow

    foreach ($p in @($procs)) {
        Write-Host "      Stopping PID $($p.Id)..." -ForegroundColor Cyan
        try {
            $p | Stop-Process -Force -ErrorAction Stop
            Write-Host "      PID $($p.Id) terminated" -ForegroundColor Green
        } catch {
            Write-Host "      [!] Failed to stop PID $($p.Id): $_" -ForegroundColor Red
            Write-Host "          Try running as Administrator" -ForegroundColor Yellow
        }
    }

    Start-Sleep -Milliseconds 500

    $remaining = Get-Process -Name $AgentName -ErrorAction SilentlyContinue
    if ($null -eq $remaining) {
        Write-Host "      All agent processes stopped" -ForegroundColor Green
    } else {
        Write-Host "      [!] Some processes could not be stopped" -ForegroundColor Red
    }
}

# ── Driver Removal ───────────────────────────────────────

function Uninstall-DriverService {
    Write-Host "  [*] Checking kernel driver..." -ForegroundColor Cyan

    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($null -eq $svc) {
        Write-Host "      Driver service is not installed" -ForegroundColor Yellow
        return
    }

    if (-not (Test-Administrator)) {
        Write-Host "      [!] Administrator privileges required for driver removal" -ForegroundColor Red
        Write-Host "          Right-click PowerShell -> Run as Administrator" -ForegroundColor Yellow
        return
    }

    $status = $svc.Status.ToString().ToLower()
    Write-Host "      Driver status: $status" -ForegroundColor Yellow

    if ($status -eq "running") {
        Write-Host "      Stopping driver service..." -ForegroundColor Cyan
        $result = sc.exe stop $ServiceName 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "      Driver stopped" -ForegroundColor Green
        } else {
            Write-Host "      [!] Stop returned: $result" -ForegroundColor Yellow
        }
        Start-Sleep -Seconds 2
    }

    Write-Host "      Removing driver service..." -ForegroundColor Cyan
    $result = sc.exe delete $ServiceName 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "      Driver service removed" -ForegroundColor Green
    } else {
        Write-Host "      [!] Failed to remove: $result" -ForegroundColor Red
    }
}

# ── Build Artifact Cleanup ───────────────────────────────

function Remove-BuildArtifacts {
    Write-Host "  [*] Cleaning build artifacts..." -ForegroundColor Cyan

    $artifacts = @(
        (Join-Path $ScriptDir "edr_agent.exe"),
        (Join-Path $ScriptDir "src\edr_agent"),
        (Join-Path $ScriptDir "test_driver_logic.exe"),
        (Join-Path $ScriptDir "test_driver_ioctl.exe")
    )
    $dirs = @(
        (Join-Path $ScriptDir "nimcache"),
        (Join-Path $ScriptDir "src\nimcache")
    )

    foreach ($f in $artifacts) {
        if (Test-Path $f) {
            Remove-Item $f -Force -Confirm:$false
            Write-Host "      Removed $(Split-Path $f -Leaf)" -ForegroundColor Green
        }
    }

    foreach ($d in $dirs) {
        if (Test-Path $d) {
            Remove-Item $d -Recurse -Force -Confirm:$false
            Write-Host "      Removed $(Split-Path $d -Leaf)/" -ForegroundColor Green
        }
    }

    Write-Host "      Build artifacts cleaned" -ForegroundColor Green
}

# ── Status Summary ───────────────────────────────────────

function Write-FinalStatus {
    Write-Host ""
    Write-Host "  Status after uninstall:" -ForegroundColor Cyan

    $agentRunning = Get-Process -Name $AgentName -ErrorAction SilentlyContinue
    Write-Host "    Agent:  " -NoNewline
    if ($null -eq $agentRunning) {
        Write-Host "NOT RUNNING" -ForegroundColor Green
    } else {
        Write-Host "STILL RUNNING ($((@($agentRunning).Count)) processes)" -ForegroundColor Red
    }

    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    Write-Host "    Driver: " -NoNewline
    if ($null -eq $svc) {
        Write-Host "NOT INSTALLED" -ForegroundColor Green
    } else {
        Write-Host "$($svc.Status)" -ForegroundColor Red
    }

    if ($Clean) {
        $agentExe = Join-Path $ScriptDir "edr_agent.exe"
        Write-Host "    Binary: " -NoNewline
        if (-not (Test-Path $agentExe)) {
            Write-Host "CLEANED" -ForegroundColor Green
        } else {
            Write-Host "EXISTS" -ForegroundColor Yellow
        }
    }

    Write-Host ""
}

# ── Main ─────────────────────────────────────────────────

Write-Banner

$doAgent  = (-not $Driver)
$doDriver = (-not $Agent)

$parts = @()
if ($doAgent)  { $parts += "agent process" }
if ($doDriver) { $parts += "kernel driver" }
if ($Clean)    { $parts += "build artifacts" }
$desc = $parts -join ", "

if (-not $Force) {
    Write-Host "  This will remove: $desc" -ForegroundColor Yellow
    Write-Host ""
    $reply = Read-Host "  Continue? (y/N)"
    if ($reply -ne "y") {
        Write-Host ""
        Write-Host "  Cancelled." -ForegroundColor Yellow
        Write-Host ""
        exit 0
    }
    Write-Host ""
}

if ($doAgent) {
    Stop-Agent
    Write-Host ""
}

if ($doDriver) {
    Uninstall-DriverService
    Write-Host ""
}

if ($Clean) {
    Remove-BuildArtifacts
    Write-Host ""
}

Write-FinalStatus

Write-Host "  [+] Uninstall complete." -ForegroundColor Green
Write-Host ""
