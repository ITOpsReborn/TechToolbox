<#
.SYNOPSIS
    Invoke-RemoteLockout.ps1 - Takes over the Windows login screen with a custom image and text.

.DESCRIPTION
    This script acts as a Win32 application deployed via Intune that replaces the Windows
    login screen with a specified image and displays configurable text. Configuration is
    read from an accompanying XML file. The script stages files to
    C:\Windows\IntuneApps\RemoteLockout and can also act as an uninstaller to rollback
    all changes and restore the built-in login experience.

.PARAMETER Mode
    Install - Applies the remote lockout configuration.
    Uninstall - Rolls back all changes and restores defaults.

.EXAMPLE
    # Install (lock the screen)
    .\Invoke-RemoteLockout.ps1 -Mode Install

    # Uninstall (restore defaults)
    .\Invoke-RemoteLockout.ps1 -Mode Uninstall

.NOTES
    Requires elevation (runs as SYSTEM via Intune).
    Logs to C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\RemoteLockout.log
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Install', 'Uninstall')]
    [string]$Mode,

    [Parameter(Mandatory = $false)]
    [string]$ConfigFile = 'RemoteLockout.xml'
)

#region Configuration
$StagingPath = 'C:\Windows\IntuneApps\RemoteLockout'
$LogPath = 'C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\RemoteLockout.log'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$XmlConfigPath = Join-Path $ScriptDir $ConfigFile
$PersonalizationRegPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization'
$LegalNoticeRegPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$BackupPath = Join-Path $StagingPath 'Backup'
#endregion

#region Logging
function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [ValidateSet('Info', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry = "[$timestamp] [$Level] $Message"

    # Write to console
    switch ($Level) {
        'Warning' { Write-Warning $Message }
        'Error' { Write-Error $Message }
        default { Write-Output $logEntry }
    }

    # Write to log file
    $logDir = Split-Path -Parent $LogPath
    if (-not (Test-Path $logDir)) {
        New-Item -Path $logDir -ItemType Directory -Force | Out-Null
    }
    Add-Content -Path $LogPath -Value $logEntry -Force
}
#endregion

#region Helper Functions
function Read-XmlConfig {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path $Path)) {
        Write-Log -Message "XML configuration file not found: $Path" -Level Error
        exit 1
    }

    try {
        [xml]$config = Get-Content -Path $Path -Raw
        $lockout = $config.RemoteLockout

        $result = @{
            LockImage = $lockout.LockImage
            Line1     = $lockout.Line1
            Line2     = $lockout.Line2
            TextColor = $lockout.TextColor
        }

        # Validate required fields
        foreach ($key in $result.Keys) {
            if ([string]::IsNullOrWhiteSpace($result[$key])) {
                Write-Log -Message "XML configuration missing required element: $key" -Level Error
                exit 1
            }
        }

        # Validate hex color format
        if ($result.TextColor -notmatch '^#[0-9A-Fa-f]{6}$') {
            Write-Log -Message "TextColor must be a valid hex color (e.g., #FFFFFF). Got: $($result.TextColor)" -Level Error
            exit 1
        }

        return $result
    }
    catch {
        Write-Log -Message "Failed to parse XML configuration: $_" -Level Error
        exit 1
    }
}

function Backup-CurrentSettings {
    Write-Log -Message 'Backing up current login screen settings...'

    if (-not (Test-Path $BackupPath)) {
        New-Item -Path $BackupPath -ItemType Directory -Force | Out-Null
    }

    $backup = @{}

    # Backup Personalization registry values
    if (Test-Path $PersonalizationRegPath) {
        $regValues = Get-ItemProperty -Path $PersonalizationRegPath -ErrorAction SilentlyContinue
        if ($regValues.LockScreenImage) {
            $backup['LockScreenImage'] = $regValues.LockScreenImage
        }
        if ($null -ne $regValues.NoChangingLockScreen) {
            $backup['NoChangingLockScreen'] = $regValues.NoChangingLockScreen
        }
    }

    # Backup Legal Notice settings
    if (Test-Path $LegalNoticeRegPath) {
        $legalValues = Get-ItemProperty -Path $LegalNoticeRegPath -ErrorAction SilentlyContinue
        if ($legalValues.LegalNoticeCaption) {
            $backup['LegalNoticeCaption'] = $legalValues.LegalNoticeCaption
        }
        if ($legalValues.LegalNoticeText) {
            $backup['LegalNoticeText'] = $legalValues.LegalNoticeText
        }
    }

    # Backup DontDisplayLastUserName setting
    $winLogonPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $winLogonValues = Get-ItemProperty -Path $winLogonPath -ErrorAction SilentlyContinue
    if ($null -ne $winLogonValues.DontDisplayLastUserName) {
        $backup['DontDisplayLastUserName'] = $winLogonValues.DontDisplayLastUserName
    }

    # Backup enabled local user accounts
    $enabledUsers = Get-LocalUser | Where-Object { $_.Enabled -eq $true } | Select-Object -ExpandProperty Name
    $backup['EnabledUsers'] = $enabledUsers

    # Backup current security policy (SeDenyInteractiveLogonRight)
    $secExportPath = Join-Path $BackupPath 'secpol_backup.inf'
    secedit /export /cfg $secExportPath /quiet 2>$null
    Write-Log -Message 'Security policy exported for backup.'

    $backup | ConvertTo-Json | Set-Content -Path (Join-Path $BackupPath 'settings.json') -Force
    Write-Log -Message 'Backup completed successfully.'
}

function Disable-InteractiveLogon {
    Write-Log -Message 'Disabling interactive logon...'

    # Hide user list on the logon screen
    Set-ItemProperty -Path $LegalNoticeRegPath -Name 'DontDisplayLastUserName' -Value 1 -Type DWord -Force
    Write-Log -Message 'User list hidden on logon screen (DontDisplayLastUserName = 1).'

    # Disable all local user accounts (except built-in system accounts that cannot be disabled)
    $usersToDisable = Get-LocalUser | Where-Object {
        $_.Enabled -eq $true -and
        $_.Name -notin @('DefaultAccount', 'WDAGUtilityAccount')
    }
    foreach ($user in $usersToDisable) {
        try {
            Disable-LocalUser -Name $user.Name
            Write-Log -Message "Disabled local user account: $($user.Name)"
        }
        catch {
            Write-Log -Message "Failed to disable user account: $($user.Name) - $_" -Level Warning
        }
    }

    # Deny interactive logon for Users and Administrators via security policy
    $secDbPath = Join-Path $StagingPath 'deny_logon.inf'
    $secContent = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Privilege Rights]
SeDenyInteractiveLogonRight = *S-1-5-32-545,*S-1-5-32-544
"@
    Set-Content -Path $secDbPath -Value $secContent -Force
    secedit /configure /db (Join-Path $StagingPath 'deny_logon.sdb') /cfg $secDbPath /overwrite /quiet 2>$null
    Write-Log -Message 'Denied interactive logon right for Users and Administrators groups.'

    # Disable Ctrl+Alt+Del bypass (require it for any logon attempt)
    Set-ItemProperty -Path $LegalNoticeRegPath -Name 'DisableCAD' -Value 0 -Type DWord -Force
    Write-Log -Message 'Ctrl+Alt+Del requirement enforced.'

    Write-Log -Message 'Interactive logon has been fully disabled.'
}

function Restore-InteractiveLogon {
    Write-Log -Message 'Restoring interactive logon capabilities...'

    $backupFile = Join-Path $BackupPath 'settings.json'

    # Restore DontDisplayLastUserName
    if (Test-Path $backupFile) {
        $backup = Get-Content -Path $backupFile -Raw | ConvertFrom-Json

        if ($null -ne $backup.DontDisplayLastUserName) {
            Set-ItemProperty -Path $LegalNoticeRegPath -Name 'DontDisplayLastUserName' -Value $backup.DontDisplayLastUserName -Type DWord -Force
        }
        else {
            Set-ItemProperty -Path $LegalNoticeRegPath -Name 'DontDisplayLastUserName' -Value 0 -Type DWord -Force
        }
        Write-Log -Message 'DontDisplayLastUserName restored.'

        # Re-enable previously enabled user accounts
        if ($backup.EnabledUsers) {
            foreach ($userName in $backup.EnabledUsers) {
                try {
                    Enable-LocalUser -Name $userName -ErrorAction Stop
                    Write-Log -Message "Re-enabled local user account: $userName"
                }
                catch {
                    Write-Log -Message "Failed to re-enable user account: $userName - $_" -Level Warning
                }
            }
        }
    }
    else {
        Set-ItemProperty -Path $LegalNoticeRegPath -Name 'DontDisplayLastUserName' -Value 0 -Type DWord -Force
        Write-Log -Message 'DontDisplayLastUserName set to 0 (no backup found).'
    }

    # Remove deny interactive logon right by restoring original security policy
    $secBackupPath = Join-Path $BackupPath 'secpol_backup.inf'
    if (Test-Path $secBackupPath) {
        $restoreDb = Join-Path $StagingPath 'restore_logon.sdb'
        secedit /configure /db $restoreDb /cfg $secBackupPath /overwrite /quiet 2>$null
        Write-Log -Message 'Security policy restored from backup (SeDenyInteractiveLogonRight).'
    }
    else {
        # No backup - remove the deny right by applying an empty privilege
        $secClearPath = Join-Path $env:TEMP 'clear_deny_logon.inf'
        $secClearContent = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Privilege Rights]
SeDenyInteractiveLogonRight =
"@
        Set-Content -Path $secClearPath -Value $secClearContent -Force
        secedit /configure /db (Join-Path $env:TEMP 'clear_deny_logon.sdb') /cfg $secClearPath /overwrite /quiet 2>$null
        Remove-Item -Path $secClearPath -Force -ErrorAction SilentlyContinue
        Write-Log -Message 'SeDenyInteractiveLogonRight cleared (no backup found).'
    }

    # Restore DisableCAD to default (0 = Ctrl+Alt+Del not required)
    Set-ItemProperty -Path $LegalNoticeRegPath -Name 'DisableCAD' -Value 1 -Type DWord -Force
    Write-Log -Message 'Ctrl+Alt+Del requirement removed (DisableCAD restored).'

    Write-Log -Message 'Interactive logon fully restored.'
}

function Set-LockScreen {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ImagePath,
        [Parameter(Mandatory = $true)]
        [string]$Line1,
        [Parameter(Mandatory = $true)]
        [string]$Line2,
        [Parameter(Mandatory = $true)]
        [string]$TextColor
    )

    # Set lock screen image via Group Policy registry keys
    if (-not (Test-Path $PersonalizationRegPath)) {
        New-Item -Path $PersonalizationRegPath -Force | Out-Null
    }

    Set-ItemProperty -Path $PersonalizationRegPath -Name 'LockScreenImage' -Value $ImagePath -Type String -Force
    Set-ItemProperty -Path $PersonalizationRegPath -Name 'NoChangingLockScreen' -Value 1 -Type DWord -Force
    Write-Log -Message "Lock screen image set to: $ImagePath"

    # Set Legal Notice text (displays on login screen before sign-in)
    if (-not (Test-Path $LegalNoticeRegPath)) {
        New-Item -Path $LegalNoticeRegPath -Force | Out-Null
    }

    Set-ItemProperty -Path $LegalNoticeRegPath -Name 'LegalNoticeCaption' -Value $Line1 -Type String -Force
    Set-ItemProperty -Path $LegalNoticeRegPath -Name 'LegalNoticeText' -Value $Line2 -Type String -Force
    Write-Log -Message "Legal notice caption set to: $Line1"
    Write-Log -Message "Legal notice text set to: $Line2"

    # Store text color in staging for reference (used by custom credential provider if applicable)
    $textConfig = @{
        Line1     = $Line1
        Line2     = $Line2
        TextColor = $TextColor
    } | ConvertTo-Json
    Set-Content -Path (Join-Path $StagingPath 'TextConfig.json') -Value $textConfig -Force
    Write-Log -Message "Text color configuration stored: $TextColor"

    # Disable lock screen spotlight and other overrides
    $lockScreenOverridePath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
    if (-not (Test-Path $lockScreenOverridePath)) {
        New-Item -Path $lockScreenOverridePath -Force | Out-Null
    }
    Set-ItemProperty -Path $lockScreenOverridePath -Name 'DisableWindowsSpotlightOnLockScreen' -Value 1 -Type DWord -Force
    Write-Log -Message 'Windows Spotlight on lock screen disabled.'

    # Disable interactive logon to prevent any user from signing in
    Disable-InteractiveLogon
}

function Restore-LockScreen {
    Write-Log -Message 'Restoring original login screen settings...'

    $backupFile = Join-Path $BackupPath 'settings.json'

    # Remove lock screen policy
    if (Test-Path $PersonalizationRegPath) {
        Remove-ItemProperty -Path $PersonalizationRegPath -Name 'LockScreenImage' -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $PersonalizationRegPath -Name 'NoChangingLockScreen' -ErrorAction SilentlyContinue
        Write-Log -Message 'Removed lock screen image policy.'

        # Remove the key if empty
        $remaining = Get-ItemProperty -Path $PersonalizationRegPath -ErrorAction SilentlyContinue
        if ($null -eq ($remaining.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' })) {
            Remove-Item -Path $PersonalizationRegPath -Force -ErrorAction SilentlyContinue
        }
    }

    # Restore Legal Notice settings
    if (Test-Path $backupFile) {
        $backup = Get-Content -Path $backupFile -Raw | ConvertFrom-Json

        if ($backup.LegalNoticeCaption) {
            Set-ItemProperty -Path $LegalNoticeRegPath -Name 'LegalNoticeCaption' -Value $backup.LegalNoticeCaption -Type String -Force
        }
        else {
            Set-ItemProperty -Path $LegalNoticeRegPath -Name 'LegalNoticeCaption' -Value '' -Type String -Force
        }

        if ($backup.LegalNoticeText) {
            Set-ItemProperty -Path $LegalNoticeRegPath -Name 'LegalNoticeText' -Value $backup.LegalNoticeText -Type String -Force
        }
        else {
            Set-ItemProperty -Path $LegalNoticeRegPath -Name 'LegalNoticeText' -Value '' -Type String -Force
        }

        Write-Log -Message 'Legal notice settings restored from backup.'
    }
    else {
        # No backup found, clear legal notice
        Set-ItemProperty -Path $LegalNoticeRegPath -Name 'LegalNoticeCaption' -Value '' -Type String -Force
        Set-ItemProperty -Path $LegalNoticeRegPath -Name 'LegalNoticeText' -Value '' -Type String -Force
        Write-Log -Message 'Legal notice settings cleared (no backup found).'
    }

    # Re-enable Windows Spotlight
    $lockScreenOverridePath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
    if (Test-Path $lockScreenOverridePath) {
        Remove-ItemProperty -Path $lockScreenOverridePath -Name 'DisableWindowsSpotlightOnLockScreen' -ErrorAction SilentlyContinue
        Write-Log -Message 'Windows Spotlight re-enabled.'
    }

    # Restore interactive logon
    Restore-InteractiveLogon
}
#endregion

#region Main Execution
Write-Log -Message "============================================"
Write-Log -Message "Invoke-RemoteLockout.ps1 - Mode: $Mode"
Write-Log -Message "============================================"

switch ($Mode) {
    'Install' {
        Write-Log -Message 'Starting Remote Lockout installation...'

        # Read configuration
        $config = Read-XmlConfig -Path $XmlConfigPath
        Write-Log -Message "Configuration loaded from: $XmlConfigPath"

        # Create staging directory
        if (-not (Test-Path $StagingPath)) {
            New-Item -Path $StagingPath -ItemType Directory -Force | Out-Null
            Write-Log -Message "Created staging directory: $StagingPath"
        }

        # Backup current settings before making changes
        Backup-CurrentSettings

        # Resolve and copy the lock screen image
        $sourceImage = $config.LockImage
        if (-not [System.IO.Path]::IsPathRooted($sourceImage)) {
            $sourceImage = Join-Path $ScriptDir $sourceImage
        }

        if (-not (Test-Path $sourceImage)) {
            Write-Log -Message "Lock screen image not found: $sourceImage" -Level Error
            exit 1
        }

        $stagedImage = Join-Path $StagingPath (Split-Path -Leaf $sourceImage)
        Copy-Item -Path $sourceImage -Destination $stagedImage -Force
        Write-Log -Message "Lock screen image staged to: $stagedImage"

        # Copy the script and XML to staging for uninstall reference
        Copy-Item -Path $MyInvocation.MyCommand.Definition -Destination $StagingPath -Force
        Copy-Item -Path $XmlConfigPath -Destination $StagingPath -Force
        Write-Log -Message 'Script and configuration staged for uninstall reference.'

        # Apply lock screen settings
        Set-LockScreen -ImagePath $stagedImage -Line1 $config.Line1 -Line2 $config.Line2 -TextColor $config.TextColor

        # Log off all user sessions to force the lock screen to appear
        Write-Log -Message 'Logging off all user sessions...'
        $sessions = query session 2>$null | Select-Object -Skip 1
        foreach ($session in $sessions) {
            if ($session -match '^\s*(\S+)\s+(\S+)\s+(\d+)') {
                $sessionId = $Matches[3]
                try {
                    logoff $sessionId /V 2>$null
                    Write-Log -Message "Logged off session ID: $sessionId"
                }
                catch {
                    Write-Log -Message "Failed to log off session ID: $sessionId - $_" -Level Warning
                }
            }
        }
        Write-Log -Message 'All user sessions have been logged off.'

        Write-Log -Message 'Remote Lockout installation completed successfully.'
        exit 0
    }

    'Uninstall' {
        Write-Log -Message 'Starting Remote Lockout uninstallation...'

        # Restore original settings
        Restore-LockScreen

        # Remove staged files
        if (Test-Path $StagingPath) {
            Remove-Item -Path $StagingPath -Recurse -Force
            Write-Log -Message "Removed staging directory: $StagingPath"
        }

        Write-Log -Message 'Remote Lockout uninstallation completed successfully.'
        exit 0
    }
}
#endregion
