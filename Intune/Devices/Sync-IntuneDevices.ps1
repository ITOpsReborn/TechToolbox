<#
.SYNOPSIS
    Initiates a sync operation for Intune-managed devices.

.DESCRIPTION
    This script triggers a sync for one or more Intune-managed devices to ensure
    they have the latest policies and configurations.

.PARAMETER DeviceNames
    Array of device names to sync.

.PARAMETER UserPrincipalName
    Sync all devices for a specific user.

.PARAMETER SyncAll
    If specified, syncs all managed devices (use with caution).

.EXAMPLE
    .\Sync-IntuneDevices.ps1 -DeviceNames @("DESKTOP-001", "LAPTOP-002")

.EXAMPLE
    .\Sync-IntuneDevices.ps1 -UserPrincipalName "john.doe@contoso.com"

.NOTES
    Requires Microsoft.Graph.DeviceManagement module and DeviceManagementManagedDevices.PrivilegedOperations.All permissions.
#>

[CmdletBinding(DefaultParameterSetName = "ByDeviceName")]
param(
    [Parameter(Mandatory = $true, ParameterSetName = "ByDeviceName")]
    [string[]]$DeviceNames,
    
    [Parameter(Mandatory = $true, ParameterSetName = "ByUser")]
    [string]$UserPrincipalName,
    
    [Parameter(Mandatory = $true, ParameterSetName = "SyncAll")]
    [switch]$SyncAll
)

try {
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
    
    $context = Get-MgContext
    if (-not $context) {
        Connect-MgGraph -Scopes "DeviceManagementManagedDevices.PrivilegedOperations.All" -NoWelcome
    }

    $devicesToSync = @()

    switch ($PSCmdlet.ParameterSetName) {
        "ByDeviceName" {
            Write-Host "Retrieving devices by name..." -ForegroundColor Cyan
            foreach ($deviceName in $DeviceNames) {
                $device = Get-MgDeviceManagementManagedDevice -Filter "deviceName eq '$deviceName'"
                if ($device) {
                    $devicesToSync += $device
                }
                else {
                    Write-Host "  ✗ Device not found: $deviceName" -ForegroundColor Red
                }
            }
        }
        
        "ByUser" {
            Write-Host "Retrieving devices for user: $UserPrincipalName..." -ForegroundColor Cyan
            $devicesToSync = Get-MgDeviceManagementManagedDevice -Filter "userPrincipalName eq '$UserPrincipalName'"
        }
        
        "SyncAll" {
            Write-Host "WARNING: Syncing ALL managed devices. This may take a while..." -ForegroundColor Yellow
            $confirm = Read-Host "Are you sure you want to continue? (yes/no)"
            if ($confirm -ne "yes") {
                Write-Host "Operation cancelled." -ForegroundColor Yellow
                return
            }
            $devicesToSync = Get-MgDeviceManagementManagedDevice -All
        }
    }

    if ($devicesToSync.Count -eq 0) {
        Write-Host "No devices found to sync." -ForegroundColor Yellow
        return
    }

    Write-Host "`nInitiating sync for $($devicesToSync.Count) device(s)..." -ForegroundColor Cyan
    
    $successCount = 0
    $failCount = 0

    foreach ($device in $devicesToSync) {
        try {
            Sync-MgDeviceManagementManagedDevice -ManagedDeviceId $device.Id
            Write-Host "  ✓ Sync initiated for: $($device.DeviceName)" -ForegroundColor Green
            $successCount++
        }
        catch {
            Write-Host "  ✗ Failed to sync: $($device.DeviceName) - $($_.Exception.Message)" -ForegroundColor Red
            $failCount++
        }
    }

    Write-Host "`nSync Summary:" -ForegroundColor Cyan
    Write-Host "  Total Devices: $($devicesToSync.Count)" -ForegroundColor White
    Write-Host "  Successful: $successCount" -ForegroundColor Green
    Write-Host "  Failed: $failCount" -ForegroundColor Red
    Write-Host "`nNote: It may take several minutes for devices to complete synchronization." -ForegroundColor Yellow
}
catch {
    Write-Error "An error occurred: $_"
    exit 1
}
