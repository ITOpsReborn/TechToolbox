<#
.SYNOPSIS
    Removes all Windows Hello for Business credentials, triggers an Intune sync,
    logs off active user sessions, and reboots the machine.

.DESCRIPTION
    This script removes all WHfB key material by clearing the NGC folder,
    restarts the Intune Management Extension service to trigger a policy
    sync, then schedules a reboot with a 3-minute delay and logs off all
    active user sessions. All actions are logged to the Intune Management
    Extension log folder.

.NOTES
    Intended to run as an Intune platform script in SYSTEM context.
    Author: Tim Knapp
#>

$ErrorActionPreference = 'Stop'

# --- Configuration ---
$NgcPath   = Join-Path $env:WinDir "ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc"
$LogFolder = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs"
$LogFile   = Join-Path $LogFolder ("Revoke-WHfBCredentials_{0}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))

# --- Logging helper ---
function Write-Log {
    param([string]$Message)
    $entry = "{0} - {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
    Add-Content -Path $LogFile -Value $entry -Encoding UTF8
    Write-Output $entry
}

# --- Ensure log folder exists ---
if (-not (Test-Path $LogFolder)) {
    New-Item -Path $LogFolder -ItemType Directory -Force | Out-Null
}

try {
    Write-Log "Script started."

    # --- Phase 1: Remove WHfB credentials ---
    if (Test-Path $NgcPath) {
        Write-Log "NGC folder found at: $NgcPath"

        # Take ownership and grant Administrators full control
        Write-Log "Taking ownership of NGC folder."
        & takeown /F $NgcPath /R /D Y 2>&1 | Out-Null
        & icacls $NgcPath /grant "BUILTIN\Administrators:(OI)(CI)F" /T /Q 2>&1 | Out-Null

        # Remove all contents
        Remove-Item -Path "$NgcPath\*" -Recurse -Force -ErrorAction SilentlyContinue
        Write-Log "WHfB credentials removed successfully."
    }
    else {
        Write-Log "NGC folder not found at: $NgcPath. No credentials to remove."
    }

    # --- Phase 2: Trigger Intune sync ---
    Write-Log "Locating MDM enrollment ID from registry."
    $EnrollmentId = (Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Enrollments" | 
        Get-ItemProperty | 
        Where-Object {$_.ProviderID -eq "MS DM Server"}).PSChildName

    if (-not $EnrollmentId) {
        Write-Log "No Intune enrollment found!"
        exit 1
    }

    Write-Log "Found enrollment ID: $EnrollmentId"
    $taskPath = "\Microsoft\Windows\EnterpriseMgmt\$EnrollmentId\"
    $taskName = "Schedule #3 created by enrollment client"
    Write-Log "Running scheduled task: $taskPath$taskName"
    Start-ScheduledTask -TaskPath $taskPath -TaskName $taskName
    Write-Log "Intune sync scheduled task started."

    # --- Phase 3: Clear cached logon credentials ---
    Write-Log "Clearing cached logon credentials from LSA cache."
    $cacheKey = "HKLM:\SECURITY\Cache"
    $entries = Get-ItemProperty -Path $cacheKey -ErrorAction SilentlyContinue
    $entries.PSObject.Properties |
        Where-Object { $_.Name -match '^NL\$\d+$' } |
        ForEach-Object {
            $zeroed = [byte[]]::new($_.Value.Length)
            Set-ItemProperty -Path $cacheKey -Name $_.Name -Value $zeroed
        }
    Write-Log "Cached logon credentials cleared."

    # Disable cached logons to prevent offline authentication
    Write-Log "Setting CachedLogonsCount to 0."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CachedLogonsCount" -Value "0" -Type String
    Write-Log "Cached logons disabled."

    # --- Phase 4: Schedule reboot and log off user sessions ---
    Write-Log "Scheduling reboot in 180 seconds."
    & shutdown /r /t 180 /f /c "Windows Hello for Business credentials have been reset. This machine will reboot in 3 minutes."

    Write-Log "Logging off active user sessions."
    $sessionIds = @(Get-Process -Name explorer -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty SessionId -Unique)

    if ($sessionIds.Count -gt 0) {
        foreach ($sessionId in $sessionIds) {
            Write-Log "Logging off session ID: $sessionId"
            & logoff $sessionId 2>&1 | Out-Null
        }
    }
    else {
        Write-Log "No active user sessions found."
    }

    Write-Log "Script completed successfully."
    exit 0
}
catch {
    Write-Log "ERROR: $($_.Exception.Message)"
    exit 1
}
