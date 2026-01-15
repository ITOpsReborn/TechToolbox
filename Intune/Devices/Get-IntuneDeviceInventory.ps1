<#
.SYNOPSIS
    Generates a comprehensive inventory report of all Intune-managed devices.

.DESCRIPTION
    This script retrieves detailed information about all devices managed by Intune
    including device properties, compliance status, last sync time, and OS information.

.PARAMETER OutputPath
    The path where the CSV report will be saved.

.PARAMETER IncludeNonCompliant
    If specified, creates a separate report for non-compliant devices only.

.EXAMPLE
    .\Get-IntuneDeviceInventory.ps1 -OutputPath "C:\Reports\Devices.csv"

.EXAMPLE
    .\Get-IntuneDeviceInventory.ps1 -IncludeNonCompliant

.NOTES
    Requires Microsoft.Graph.DeviceManagement module and DeviceManagementManagedDevices.Read.All permissions.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\IntuneDeviceInventory_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeNonCompliant
)

try {
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
    
    $context = Get-MgContext
    if (-not $context) {
        Connect-MgGraph -Scopes "DeviceManagementManagedDevices.Read.All" -NoWelcome
    }

    Write-Host "Retrieving managed devices from Intune..." -ForegroundColor Cyan
    
    # Get all managed devices
    $devices = Get-MgDeviceManagementManagedDevice -All | Select-Object `
        Id, DeviceName, UserDisplayName, UserPrincipalName, `
        OperatingSystem, OSVersion, Model, Manufacturer, SerialNumber, `
        ComplianceState, LastSyncDateTime, EnrolledDateTime, `
        ManagementAgent, DeviceEnrollmentType, AzureAdDeviceId, `
        IsEncrypted, IsSupervised, PhoneNumber, Imei

    Write-Host "Found $($devices.Count) managed devices" -ForegroundColor Green
    
    # Export all devices
    $devices | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host "✓ Full device inventory exported to: $OutputPath" -ForegroundColor Green
    
    # Statistics
    $compliantCount = ($devices | Where-Object { $_.ComplianceState -eq "compliant" }).Count
    $nonCompliantCount = ($devices | Where-Object { $_.ComplianceState -ne "compliant" }).Count
    $windowsCount = ($devices | Where-Object { $_.OperatingSystem -like "*Windows*" }).Count
    $iosCount = ($devices | Where-Object { $_.OperatingSystem -eq "iOS" -or $_.OperatingSystem -eq "iPadOS" }).Count
    $androidCount = ($devices | Where-Object { $_.OperatingSystem -eq "Android" }).Count
    $macCount = ($devices | Where-Object { $_.OperatingSystem -eq "macOS" }).Count
    
    Write-Host "`nDevice Summary:" -ForegroundColor Cyan
    Write-Host "  Total Devices: $($devices.Count)" -ForegroundColor White
    Write-Host "  Compliant: $compliantCount" -ForegroundColor Green
    Write-Host "  Non-Compliant: $nonCompliantCount" -ForegroundColor Red
    Write-Host "`nBy Operating System:" -ForegroundColor Cyan
    Write-Host "  Windows: $windowsCount" -ForegroundColor White
    Write-Host "  iOS/iPadOS: $iosCount" -ForegroundColor White
    Write-Host "  Android: $androidCount" -ForegroundColor White
    Write-Host "  macOS: $macCount" -ForegroundColor White
    
    # Export non-compliant devices if requested
    if ($IncludeNonCompliant) {
        $nonCompliantDevices = $devices | Where-Object { $_.ComplianceState -ne "compliant" }
        if ($nonCompliantDevices.Count -gt 0) {
            $nonCompliantPath = ".\IntuneNonCompliantDevices_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
            $nonCompliantDevices | Export-Csv -Path $nonCompliantPath -NoTypeInformation -Encoding UTF8
            Write-Host "`n✓ Non-compliant devices report exported to: $nonCompliantPath" -ForegroundColor Yellow
        }
    }
}
catch {
    Write-Error "An error occurred: $_"
    exit 1
}
