<#
.SYNOPSIS
    MostShittyEDR kernel driver install/uninstall script.

.DESCRIPTION
    Installs or removes the MostShittyEDR kernel driver. Requires:
      - Administrator privileges
      - Test-signing enabled (bcdedit /set testsigning on)
      - A compiled driver.sys file

.PARAMETER Install
    Install and start the driver.

.PARAMETER Uninstall
    Stop and remove the driver.

.PARAMETER DriverPath
    Path to the driver .sys file. Default: .\driver.sys

.PARAMETER Status
    Show current driver status.

.EXAMPLE
    .\install_driver.ps1 -Install
    .\install_driver.ps1 -Install -DriverPath C:\build\MostShittyEDR.sys
    .\install_driver.ps1 -Uninstall
    .\install_driver.ps1 -Status
#>

[CmdletBinding(DefaultParameterSetName = 'Status')]
param(
    [Parameter(ParameterSetName = 'Install')]
    [switch]$Install,

    [Parameter(ParameterSetName = 'Uninstall')]
    [switch]$Uninstall,

    [Parameter(ParameterSetName = 'Install')]
    [string]$DriverPath = ".\driver.sys",

    [Parameter(ParameterSetName = 'Status')]
    [switch]$Status
)

$ServiceName = "MostShittyEDR"
$DevicePath  = "\\.\MostShittyEDR"

# ── Helpers ──────────────────────────────────────────────

function Write-Banner {
    Write-Host ""
    Write-Host "  MostShittyEDR - Driver Installer" -ForegroundColor Cyan
    Write-Host "  ================================" -ForegroundColor Cyan
    Write-Host ""
}

function Test-Administrator {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-TestSigning {
    $output = bcdedit /enum "{current}" 2>&1 | Out-String
    return $output -match "testsigning\s+Yes"
}

function Get-DriverStatus {
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($null -eq $svc) {
        return "not_installed"
    }
    return $svc.Status.ToString().ToLower()
}

function Write-Status {
    $status = Get-DriverStatus
    switch ($status) {
        "not_installed" {
            Write-Host "  Driver status: " -NoNewline
            Write-Host "NOT INSTALLED" -ForegroundColor Yellow
        }
        "running" {
            Write-Host "  Driver status: " -NoNewline
            Write-Host "RUNNING" -ForegroundColor Green
        }
        "stopped" {
            Write-Host "  Driver status: " -NoNewline
            Write-Host "STOPPED" -ForegroundColor Red
        }
        default {
            Write-Host "  Driver status: $status" -ForegroundColor Yellow
        }
    }

    $ts = Test-TestSigning
    Write-Host "  Test-signing:  " -NoNewline
    if ($ts) {
        Write-Host "ENABLED" -ForegroundColor Green
    } else {
        Write-Host "DISABLED" -ForegroundColor Red
    }
    Write-Host ""
}

# ── Install ──────────────────────────────────────────────

function Install-Driver {
    Write-Banner

    if (-not (Test-Administrator)) {
        Write-Host "  [!] This script requires Administrator privileges." -ForegroundColor Red
        Write-Host "      Right-click PowerShell -> Run as Administrator" -ForegroundColor Yellow
        Write-Host ""
        exit 1
    }

    if (-not (Test-TestSigning)) {
        Write-Host "  [!] Test-signing is not enabled." -ForegroundColor Red
        Write-Host "      Run: bcdedit /set testsigning on" -ForegroundColor Yellow
        Write-Host "      Then reboot." -ForegroundColor Yellow
        Write-Host ""
        $reply = Read-Host "  Enable test-signing now and reboot? (y/N)"
        if ($reply -eq "y") {
            bcdedit /set testsigning on
            Write-Host ""
            Write-Host "  [+] Test-signing enabled. Rebooting in 10 seconds..." -ForegroundColor Green
            Write-Host "      Run this script again after reboot." -ForegroundColor Yellow
            shutdown /r /t 10 /c "MostShittyEDR: Enabling test-signing mode"
        }
        exit 1
    }

    $resolvedPath = Resolve-Path $DriverPath -ErrorAction SilentlyContinue
    if ($null -eq $resolvedPath) {
        Write-Host "  [!] Driver file not found: $DriverPath" -ForegroundColor Red
        Write-Host ""
        Write-Host "  Build the driver with WDK first:" -ForegroundColor Yellow
        Write-Host "    1. Open src/driver/ in Visual Studio with WDK" -ForegroundColor Gray
        Write-Host "    2. Build x64 Release" -ForegroundColor Gray
        Write-Host "    3. Copy the .sys file here" -ForegroundColor Gray
        Write-Host ""
        exit 1
    }
    $fullPath = $resolvedPath.Path

    $status = Get-DriverStatus
    if ($status -eq "running") {
        Write-Host "  [*] Driver is already running." -ForegroundColor Green
        Write-Status
        exit 0
    }

    if ($status -ne "not_installed") {
        Write-Host "  [*] Removing existing service..." -ForegroundColor Yellow
        sc.exe stop $ServiceName 2>$null | Out-Null
        sc.exe delete $ServiceName 2>$null | Out-Null
        Start-Sleep -Seconds 1
    }

    Write-Host "  [*] Driver path: $fullPath" -ForegroundColor Cyan
    Write-Host ""

    Write-Host "  [1/3] Creating kernel service..." -ForegroundColor Cyan
    $result = sc.exe create $ServiceName type= kernel binPath= "$fullPath" 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  [!] Failed to create service: $result" -ForegroundColor Red
        exit 1
    }
    Write-Host "        $result" -ForegroundColor Green

    Write-Host "  [2/3] Starting driver..." -ForegroundColor Cyan
    $result = sc.exe start $ServiceName 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  [!] Failed to start driver: $result" -ForegroundColor Red
        Write-Host "      Check Event Viewer -> System for details." -ForegroundColor Yellow
        sc.exe delete $ServiceName 2>$null | Out-Null
        exit 1
    }
    Write-Host "        $result" -ForegroundColor Green

    Write-Host "  [3/3] Verifying device..." -ForegroundColor Cyan
    Start-Sleep -Milliseconds 500
    $status = Get-DriverStatus
    if ($status -eq "running") {
        Write-Host "        Device \\.\MostShittyEDR is ready" -ForegroundColor Green
    } else {
        Write-Host "        Warning: service status is $status" -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "  [+] Installation complete!" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Next steps:" -ForegroundColor Cyan
    Write-Host "    .\edr_agent.exe --driver --verbose" -ForegroundColor White
    Write-Host ""
}

# ── Uninstall ────────────────────────────────────────────

function Uninstall-Driver {
    Write-Banner

    if (-not (Test-Administrator)) {
        Write-Host "  [!] This script requires Administrator privileges." -ForegroundColor Red
        exit 1
    }

    $status = Get-DriverStatus
    if ($status -eq "not_installed") {
        Write-Host "  [*] Driver is not installed." -ForegroundColor Yellow
        Write-Host ""
        exit 0
    }

    Write-Host "  [1/2] Stopping driver..." -ForegroundColor Cyan
    if ($status -eq "running") {
        $result = sc.exe stop $ServiceName 2>&1
        Write-Host "        $result" -ForegroundColor Yellow
        Start-Sleep -Seconds 2
    } else {
        Write-Host "        Already stopped" -ForegroundColor Yellow
    }

    Write-Host "  [2/2] Removing service..." -ForegroundColor Cyan
    $result = sc.exe delete $ServiceName 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  [!] Failed to delete service: $result" -ForegroundColor Red
        exit 1
    }
    Write-Host "        $result" -ForegroundColor Green

    Write-Host ""
    Write-Host "  [+] Driver uninstalled." -ForegroundColor Green
    Write-Host ""
}

# ── Main ─────────────────────────────────────────────────

if ($Install) {
    Install-Driver
} elseif ($Uninstall) {
    Uninstall-Driver
} else {
    Write-Banner
    Write-Status

    Write-Host "  Usage:" -ForegroundColor Cyan
    Write-Host "    .\install_driver.ps1 -Install              # Install and start" -ForegroundColor White
    Write-Host "    .\install_driver.ps1 -Install -DriverPath X:\driver.sys" -ForegroundColor White
    Write-Host "    .\install_driver.ps1 -Uninstall            # Stop and remove" -ForegroundColor White
    Write-Host "    .\install_driver.ps1 -Status               # Show status" -ForegroundColor White
    Write-Host ""
}
