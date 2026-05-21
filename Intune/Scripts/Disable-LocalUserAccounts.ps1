<#
.SYNOPSIS
    Disables all local user accounts except the Windows LAPS managed account.

.DESCRIPTION
    Identifies the Windows LAPS account by name, then disables every other
    local user account. All actions are logged to the Intune Management
    Extension log folder.

.NOTES
    Intended to run as an Intune remediation or platform script.
#>

# --- Configuration ---
$LAPSAccountName = "WLapsAdmin"
$LogFolder = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs"
$LogFile = Join-Path $LogFolder "Disable-LocalUserAccounts.log"

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

Write-Log "Script started. LAPS account name: $LAPSAccountName"

try {
    $localUsers = Get-LocalUser
    Write-Log "Found $($localUsers.Count) local user account(s)."

    foreach ($user in $localUsers) {
        if ($user.Name -eq $LAPSAccountName) {
            Write-Log "Skipping LAPS account: $($user.Name)"
            continue
        }

        if ($user.Enabled) {
            Disable-LocalUser -Name $user.Name
            Write-Log "Disabled account: $($user.Name)"
        }
        else {
            Write-Log "Account already disabled: $($user.Name)"
        }
    }

    Write-Log "Script completed successfully."
    exit 0
}
catch {
    Write-Log "ERROR: $($_.Exception.Message)"
    exit 1
}
