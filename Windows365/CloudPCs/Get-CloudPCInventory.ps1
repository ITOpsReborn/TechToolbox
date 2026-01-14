<#
.SYNOPSIS
    Generates a comprehensive inventory report of all Windows 365 Cloud PCs.

.DESCRIPTION
    This script retrieves detailed information about all Cloud PCs including
    provisioning status, user assignments, specifications, and last activity.

.PARAMETER OutputPath
    The path where the CSV report will be saved.

.PARAMETER IncludeHealthChecks
    If specified, includes Azure network connection health check results.

.EXAMPLE
    .\Get-CloudPCInventory.ps1 -OutputPath "C:\Reports\CloudPCs.csv"

.EXAMPLE
    .\Get-CloudPCInventory.ps1 -IncludeHealthChecks

.NOTES
    Requires Microsoft.Graph.DeviceManagement.Actions module and CloudPC.Read.All permissions.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\CloudPC_Inventory_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeHealthChecks
)

try {
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
    
    $context = Get-MgContext
    if (-not $context) {
        Connect-MgGraph -Scopes "CloudPC.Read.All" -NoWelcome
    }

    Write-Host "Retrieving Cloud PCs..." -ForegroundColor Cyan
    
    # Get all Cloud PCs
    $cloudPCs = Get-MgDeviceManagementVirtualEndpointCloudPC -All
    
    Write-Host "Found $($cloudPCs.Count) Cloud PCs" -ForegroundColor Green

    $inventory = @()

    foreach ($pc in $cloudPCs) {
        $inventory += [PSCustomObject]@{
            DisplayName          = $pc.DisplayName
            Id                   = $pc.Id
            UserPrincipalName    = $pc.UserPrincipalName
            ManagedDeviceName    = $pc.ManagedDeviceName
            Status               = $pc.Status
            ProvisioningPolicyId = $pc.ProvisioningPolicyId
            ServicePlanType      = $pc.ServicePlanType
            ImageDisplayName     = $pc.ImageDisplayName
            LastModifiedDateTime = $pc.LastModifiedDateTime
            LastLoginResult      = $pc.LastLoginResult
            LastRemoteActionResult = $pc.LastRemoteActionResult
            GracePeriodEndDateTime = $pc.GracePeriodEndDateTime
            AadDeviceId          = $pc.AadDeviceId
        }
    }

    # Export to CSV
    $inventory | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    
    Write-Host "✓ Inventory exported successfully to: $OutputPath" -ForegroundColor Green
    
    # Display statistics
    $provisionedCount = ($cloudPCs | Where-Object { $_.Status -eq "provisioned" }).Count
    $provisioningCount = ($cloudPCs | Where-Object { $_.Status -eq "provisioning" }).Count
    $gracePeriodCount = ($cloudPCs | Where-Object { $_.Status -eq "inGracePeriod" }).Count
    $failedCount = ($cloudPCs | Where-Object { $_.Status -eq "failed" }).Count
    
    Write-Host "`nCloud PC Summary:" -ForegroundColor Cyan
    Write-Host "  Total Cloud PCs: $($cloudPCs.Count)" -ForegroundColor White
    Write-Host "  Provisioned: $provisionedCount" -ForegroundColor Green
    Write-Host "  Provisioning: $provisioningCount" -ForegroundColor Yellow
    Write-Host "  In Grace Period: $gracePeriodCount" -ForegroundColor Magenta
    Write-Host "  Failed: $failedCount" -ForegroundColor Red

    # Health checks if requested
    if ($IncludeHealthChecks) {
        Write-Host "`nRetrieving Azure Network Connection health status..." -ForegroundColor Cyan
        
        $connections = Get-MgDeviceManagementVirtualEndpointOnPremisesConnection -All
        
        $healthReport = @()
        foreach ($conn in $connections) {
            $healthReport += [PSCustomObject]@{
                ConnectionName   = $conn.DisplayName
                HealthCheckStatus = $conn.HealthCheckStatus
                LastHealthCheck  = $conn.HealthCheckStatusDetails.LastHealthCheckDateTime
                SubscriptionId   = $conn.SubscriptionId
                ResourceGroupId  = $conn.ResourceGroupId
            }
        }
        
        $healthPath = ".\CloudPC_NetworkHealth_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $healthReport | Export-Csv -Path $healthPath -NoTypeInformation -Encoding UTF8
        
        Write-Host "✓ Network health report exported to: $healthPath" -ForegroundColor Green
    }
}
catch {
    Write-Error "An error occurred: $_"
    exit 1
}
