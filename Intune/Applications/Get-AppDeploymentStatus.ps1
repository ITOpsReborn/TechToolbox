<#
.SYNOPSIS
    Gets application deployment status report from Intune.

.DESCRIPTION
    This script generates a report showing the installation status of applications
    across all managed devices in Intune.

.PARAMETER ApplicationName
    Optional filter for a specific application name.

.PARAMETER OutputPath
    The path where the CSV report will be saved.

.EXAMPLE
    .\Get-AppDeploymentStatus.ps1 -OutputPath "C:\Reports\Apps.csv"

.EXAMPLE
    .\Get-AppDeploymentStatus.ps1 -ApplicationName "Microsoft Edge" -OutputPath "C:\Reports\Edge.csv"

.NOTES
    Requires Microsoft.Graph.DeviceManagement module and DeviceManagementApps.Read.All permissions.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ApplicationName,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\AppDeploymentStatus_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

try {
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
    
    $context = Get-MgContext
    if (-not $context) {
        Connect-MgGraph -Scopes "DeviceManagementApps.Read.All", "DeviceManagementManagedDevices.Read.All" -NoWelcome
    }

    Write-Host "Retrieving mobile app information..." -ForegroundColor Cyan
    
    # Get all mobile apps
    $apps = Get-MgDeviceAppManagementMobileApp -All
    
    if ($ApplicationName) {
        $apps = $apps | Where-Object { $_.DisplayName -like "*$ApplicationName*" }
    }

    Write-Host "Found $($apps.Count) application(s)" -ForegroundColor Green

    $deploymentStatus = @()

    foreach ($app in $apps) {
        Write-Host "Processing: $($app.DisplayName)..." -ForegroundColor Cyan
        
        # Get install status for this app
        try {
            $installStatus = Get-MgDeviceAppManagementMobileAppInstallSummary -MobileAppId $app.Id
            
            if ($installStatus) {
                $deploymentStatus += [PSCustomObject]@{
                    ApplicationName     = $app.DisplayName
                    ApplicationId       = $app.Id
                    Publisher           = $app.Publisher
                    InstalledDevices    = $installStatus.InstalledDeviceCount
                    FailedDevices       = $installStatus.FailedDeviceCount
                    PendingDevices      = $installStatus.PendingInstallDeviceCount
                    NotApplicable       = $installStatus.NotApplicableDeviceCount
                    NotInstalledDevices = $installStatus.NotInstalledDeviceCount
                    CreatedDate         = $app.CreatedDateTime
                }
            }
        }
        catch {
            # Expected for apps without install summaries (e.g., not yet deployed)
            if ($_.Exception.Message -notlike "*not found*") {
                Write-Host "  Warning: Could not get install status for $($app.DisplayName): $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
    }

    # Export to CSV
    $deploymentStatus | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    
    Write-Host "`n✓ Report exported successfully to: $OutputPath" -ForegroundColor Green
    
    # Display summary
    $totalInstalled = ($deploymentStatus | Measure-Object -Property InstalledDevices -Sum).Sum
    $totalFailed = ($deploymentStatus | Measure-Object -Property FailedDevices -Sum).Sum
    $totalPending = ($deploymentStatus | Measure-Object -Property PendingDevices -Sum).Sum
    
    Write-Host "`nDeployment Summary:" -ForegroundColor Cyan
    Write-Host "  Applications: $($deploymentStatus.Count)" -ForegroundColor White
    Write-Host "  Total Installed: $totalInstalled" -ForegroundColor Green
    Write-Host "  Total Failed: $totalFailed" -ForegroundColor Red
    Write-Host "  Total Pending: $totalPending" -ForegroundColor Yellow
}
catch {
    Write-Error "An error occurred: $_"
    exit 1
}
