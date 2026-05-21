<#
.SYNOPSIS
    Disables Delivery Optimization verbose logging on the device.

.DESCRIPTION
    Executes the built-in Disable-DeliveryOptimizationVerboseLogs cmdlet to turn on
    verbose-level Delivery Optimization event log channels. Results and errors are
    written to the Intune Management Extension log directory.

.AUTHOR
    Tim Knapp

.NOTES
    Log Path: C:\ProgramData\Microsoft\IntuneManagementExtension\Logs
#>

$LogDir  = 'C:\ProgramData\Microsoft\IntuneManagementExtension\Logs'
$LogFile = Join-Path -Path $LogDir -ChildPath 'Disable-DeliveryOptimizationVerboseLogs.log'

function Write-Log {
    param (
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet('INFO','WARN','ERROR')]
        [string]$Level = 'INFO'
    )

    $entry = "[{0}] [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message

    if (!(Test-Path -Path $LogDir)) {
        New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
    }

    Add-Content -Path $LogFile -Value $entry -Force
    Write-Output $entry
}

try {
    Write-Log -Message 'Starting Disable-DeliveryOptimizationVerboseLogs.'
    Disable-DeliveryOptimizationVerboseLogs -Force
    Write-Log -Message 'Successfully Disabled Delivery Optimization verbose logging.'
    exit 0
}
catch {
    Write-Log -Level 'ERROR' -Message "Failed to Disable Delivery Optimization verbose logging. $($_.Exception.Message)"
    exit 1
}
